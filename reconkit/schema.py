"""Shared data model — the common language every module speaks.

Three nested entities describe what a scan discovers:

    Asset   a host reachable on the network (resolved from a domain, IP or CIDR)
      └─ Service   an open port + the software fingerprinted behind it
           └─ Finding   something worth reporting about that service (e.g. a CVE)

Each `Finding` carries a stable `fingerprint`: a hash of its *identifying* fields
only (which machine, which port, which issue), so the same issue hashes identically
across scans. That is what later lets us diff runs — detect a reappearing issue (a
fake fix) or a brand-new one — without re-reading the whole database. See GHI-CHU.md
section 5 and docs/LO-TRINH-HOC.md, lesson 4.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Severity of a finding, ordered from least to most serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """What a plugin is allowed to touch for one scan, as decided by the scope guard.

    Plugins never choose their own targets: they scan `addresses` (minus `exclude`)
    and nothing else. Names are resolved once, by the scope guard, so the address a
    plugin scans is the very address that was checked.
    """

    requested: str  # what the user asked for, e.g. "scanme.lab" or "10.0.0.0/24"
    addresses: tuple[str, ...]  # in-scope IPs / CIDR ranges to scan
    exclude: tuple[str, ...] = ()  # denied IPs / ranges inside `addresses`
    hostname: str | None = None  # set when the user asked for a name


@dataclass(frozen=True, slots=True)
class RawOutput:
    """What a tool actually printed, untouched: the proof behind a run's results.

    Everything else in a run is ReconKit's *reading* of this. Keeping the original
    lets a person check a finding by hand, lets a parser bug be found after the fact,
    and lets old scans be re-read when the parser learns something new.
    """

    plugin: str  # which scanner produced it, e.g. "nmap"
    format: str  # how to read `content`, e.g. "nmap-xml"
    command: tuple[str, ...]  # the exact argument list that was run
    content: str  # the tool's output (stdout)
    stderr: str = ""  # its warnings and errors

    @property
    def sha256(self) -> str:
        """Hash of `content`: shows that stored evidence was not altered."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def size(self) -> int:
        """Size of `content` in bytes (UTF-8)."""
        return len(self.content.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class Service:
    """An open port on an asset and the software fingerprinted behind it."""

    port: int
    protocol: str = "tcp"  # "tcp" | "udp"
    state: str = "open"
    name: str | None = None  # e.g. "ssh", "http"
    product: str | None = None  # e.g. "OpenSSH"
    version: str | None = None  # e.g. "7.4"
    cpe: str | None = None  # e.g. "cpe:/a:openbsd:openssh:7.4"
    banner: str | None = None


# Which recipe a fingerprint was made with. Fingerprints are only comparable within
# one scheme, so every fingerprint says which one it is ("v2:<sha256>"). Scheme 1
# (plain hex, no prefix) also hashed the title, product and version. Bump this whenever
# `Finding.identity()` changes what it returns.
FINGERPRINT_SCHEME = 2


@dataclass(slots=True)
class Finding:
    """Something worth reporting about a service (a CVE match, a weak config, ...).

    `fingerprint` answers one question across scans: "is this the same issue as last
    time?". It is derived from *where* the issue is and *which* issue it is, and from
    nothing a person may reword or a patch may change — see :meth:`identity`.
    """

    asset: str  # host the finding belongs to, e.g. "api.example.com"
    title: str  # short human label, e.g. "OpenSSH 7.4 - user enumeration"
    severity: Severity = Severity.INFO
    service: Service | None = None
    cve: str | None = None  # e.g. "CVE-2018-15473"
    description: str = ""
    # What was observed that led to this finding, in words a person can check
    # against the run's raw output. NOT part of the fingerprint.
    evidence: str = ""
    fingerprint: str = ""
    # The check that produced the finding when it is not a CVE: an identifier that
    # stays the same from run to run, e.g. a nuclei template id.
    rule_id: str | None = None
    # Address of the host; the orchestrator fills it in from the asset.
    ip: str | None = None

    def identity(self) -> dict[str, str | int | None]:
        """What makes this finding *this* finding, from one scan to the next.

        - **where**: the machine (its address; its name only if no address is known)
          and the port + protocol. One name can front several machines, and one
          machine can be scanned by name or by address: the address is the machine.
        - **what**: the CVE, else the rule id of the check, else — for a finding with
          neither — its title.

        Deliberately left out: the title and description (rewording an entry must not
        turn an old issue into a new one), severity (scores get revised), evidence,
        and the product version — a server upgraded from one vulnerable version to
        another still has the same open issue, not a new one.
        """
        svc = self.service
        return {
            "scheme": FINGERPRINT_SCHEME,
            "asset": _asset_key(self.ip, self.asset),
            "port": svc.port if svc else None,
            "protocol": svc.protocol.lower() if svc else None,
            "check": self._check_key(),
        }

    def _check_key(self) -> str:
        if self.cve and self.cve.strip():
            return f"cve:{self.cve.strip().upper()}"
        if self.rule_id and self.rule_id.strip():
            return f"rule:{self.rule_id.strip()}"
        # Last resort, and a weak one: the wording *is* the identity here. A check
        # that reports neither a CVE nor a rule id should be given a rule id.
        return f"title:{' '.join(self.title.split()).casefold()}"

    def compute_fingerprint(self) -> str:
        """Return this finding's fingerprint, "v<scheme>:<sha256 hex>" (and set it)."""
        canonical = json.dumps(self.identity(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.fingerprint = f"v{FINGERPRINT_SCHEME}:{digest}"
        return self.fingerprint


def _asset_key(ip: str | None, host: str) -> str:
    """One spelling per machine: the address if known, else the name."""
    if ip:
        try:
            # "2001:DB8::1" and "2001:db8:0:0:0:0:0:1" are the same address.
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip.strip().lower()
    return host.strip().lower().rstrip(".")


@dataclass(frozen=True, slots=True)
class Hop:
    """One router on the network path from the scanner to a host (traceroute).

    A hop is *seen*, never scanned: traceroute sends its probes to the in-scope host
    with a small TTL, and each router on the way that drops one answers "time
    exceeded". No packet is ever addressed to the hop itself, so a hop needs no scope
    entry — but it is also not an asset, and nothing is concluded about it.
    """

    ttl: int  # distance from the scanner: 1 = the first router
    ip: str | None = None  # None when the tool saw an answer but gave no address
    rtt_ms: float | None = None  # round-trip time; None when not measured for this host
    # Reverse-DNS (PTR) name of the hop, for display only: whoever owns the address
    # chooses it, so it identifies nothing.
    name: str | None = None


@dataclass(slots=True)
class Asset:
    """A host discovered during recon, with the services found on it."""

    host: str  # domain or IP, e.g. "api.example.com" or "203.0.113.10"
    ip: str | None = None
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # The path from the scanner to this host, ordered by TTL, when traceroute ran.
    # Hops that never answered are missing, so the TTLs can have gaps. The last hop
    # is usually the host itself.
    route: list[Hop] = field(default_factory=list)
