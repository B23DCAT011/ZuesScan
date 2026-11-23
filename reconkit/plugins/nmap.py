"""nmap adapter — port/service scan via `nmap -oX`.

`scan()` runs nmap and turns its XML into one `Asset` per host, handing the XML itself
back as evidence; `parse_xml()` does the parsing from an XML string, as a pure
function, so the parsing logic is tested without nmap installed (see
tests/data/nmap_sample.xml, nmap_two_hosts.xml).

Safety: the scope guard decides the exact addresses to scan *before* a plugin is
called, and nmap receives those addresses, never a name it would resolve again. nmap
is invoked with an argument list (never a shell string), so a target cannot be used to
inject extra commands.

How the scan is run (which ports, how fast, which extras) comes from a
:class:`~reconkit.profiles.ScanProfile`; the default is the `standard` profile.

Traceroute (profile `full`, or `traceroute=True`) adds `--traceroute`: after the port
scan nmap sends probes to each live host with increasing TTL and records the routers
that answer, which is what draws "scanner -> routers -> network" on the map. Its
probes are addressed to the in-scope host only. It needs raw sockets (root on Linux,
Npcap on Windows); without them, or for a local target, nmap reports no route.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import re
import shutil
import subprocess
import time
from dataclasses import replace
from xml.etree import ElementTree as ET

from reconkit.plugins.base import ScanError, ScanResult
from reconkit.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from reconkit.schema import Asset, Hop, RawOutput, ScanTarget, Service

log = logging.getLogger(__name__)

# nmap was told it may open raw sockets (root, NMAP_PRIVILEGED, a file capability) but
# the system said no: say how to give it that right instead of leaving "QUITTING!".
_NO_RAW_SOCKET = re.compile(
    r"Failed to open device|Operation not permitted|requires root|socket troubles",
    re.IGNORECASE,
)
RAW_SOCKET_HINT = (
    " (nmap may not open raw sockets here: run it as root or give it CAP_NET_RAW; in "
    "Docker, the scanning container needs --cap-add NET_RAW and no-new-privileges off)"
)


class NmapPlugin:
    """Scanner plugin backed by the `nmap` binary."""

    name = "nmap"

    def __init__(self, profile: ScanProfile | None = None) -> None:
        self.profile = profile if profile is not None else BUILTIN[DEFAULT_PROFILE]

    @property
    def timeout(self) -> int:
        """Seconds before the whole nmap run is stopped."""
        return self.profile.timeout

    @property
    def traceroute(self) -> bool:
        return self.profile.traceroute

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def version(self) -> str | None:
        """nmap's version as it reports it (`nmap --version`), e.g. "7.92"."""
        try:
            proc = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return None  # an unknown version must never stop a scan
        match = re.search(r"Nmap version (\S+)", proc.stdout)
        return match.group(1) if match else None

    def _command(self, target: ScanTarget) -> list[str]:
        # Only addresses reach nmap, never a name: nmap would resolve a name again
        # by itself, possibly to an address the scope guard never saw.
        exclude = ["--exclude", ",".join(target.exclude)] if target.exclude else []
        ipv6 = ["-6"] if target.addresses and _version(target.addresses[0]) == 6 else []
        return [
            "nmap",
            *ipv6,
            *self.profile.nmap_args(),
            "-oX",
            "-",
            *exclude,
            *target.addresses,
        ]

    def scan(self, target: ScanTarget) -> ScanResult:
        """Run nmap against `target`; return one `Asset` per host that responded,
        and nmap's XML as evidence.

        nmap scans IPv4 or IPv6 in one run, never both (`-6`): a dual-stack target is
        scanned once per address family and the results joined. If one family has no
        host answering (common: an AAAA record the scanner cannot reach), that is noted,
        not fatal; it fails the scan only if no family answered at all.

        Every failure surfaces as `ScanError`.
        """
        if not self.is_available():
            raise ScanError("nmap is not installed or not on PATH", plugin=self.name)
        parts = _by_family(target)
        results: list[ScanResult] = []
        silent: list[ScanError] = []
        for part in parts:
            try:
                results.append(self._scan(part))
            except ScanError as exc:
                if exc.no_response and len(parts) > 1:
                    silent.append(exc)
                    continue
                raise
        if not results:
            raise silent[0]
        merged = ScanResult(
            assets=[a for r in results for a in r.assets],
            raw=[o for r in results for o in r.raw],
        )
        for quiet in silent:
            if quiet.output is not None:
                merged.raw.append(quiet.output)  # the proof that nothing answered
            merged.notes.append(f"{quiet} (the other address family answered)")
            log.warning("%s", quiet, extra={"event": "nmap.family_silent"})
        return merged

    def _scan(self, target: ScanTarget) -> ScanResult:
        """One nmap run, over addresses of a single family."""
        asked = target.requested
        if len(target.addresses) and _version(target.addresses[0]) == 6:
            asked += " over IPv6"
        command = self._command(target)
        log.debug("running %s", " ".join(command), extra={"event": "nmap.run"})
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                # nmap writes UTF-8 XML; decode it as such instead of the Windows
                # locale codepage, and never crash on a stray byte in a banner.
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            # What nmap printed before it was stopped is incomplete, but it is still
            # the record of what was probed: keep it with the failed run.
            partial = _text(exc.stdout)
            raise ScanError(
                f"nmap timed out after {self.timeout}s scanning {asked}",
                plugin=self.name,
                stderr=_text(exc.stderr).strip() or None,
                output=self._raw(command, partial, _text(exc.stderr)) if partial else None,
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip() or None
            hint = RAW_SOCKET_HINT if stderr and _NO_RAW_SOCKET.search(stderr) else ""
            raise ScanError(
                f"nmap exited with code {exc.returncode} scanning {asked}{hint}",
                plugin=self.name,
                stderr=stderr,
                output=self._raw(command, exc.stdout or "", exc.stderr or ""),
            ) from exc
        except OSError as exc:
            # The binary vanished or is not executable between the check and the call;
            # or it carries a file capability this process may not have (EPERM).
            hint = RAW_SOCKET_HINT if exc.errno == errno.EPERM else ""
            raise ScanError(f"could not start nmap: {exc}{hint}", plugin=self.name) from exc

        log.debug(
            "nmap finished in %.1f s, %d bytes of XML",
            time.monotonic() - started,
            len(proc.stdout),
            extra={"event": "nmap.done"},
        )
        stderr = proc.stderr.strip() or None
        if stderr:
            log.info("nmap said: %s", stderr.replace("\n", " | "), extra={"event": "nmap.stderr"})
        # From here on nmap has said something: whatever we conclude from it, right
        # or wrong, the output itself is kept.
        raw = self._raw(command, proc.stdout, proc.stderr)
        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError as exc:
            # Truncated or non-XML output: report it rather than guess at a result.
            raise ScanError(
                f"nmap produced unreadable XML scanning {asked}: {exc}",
                plugin=self.name,
                stderr=stderr,
                output=raw,
            ) from exc

        # nmap exits 0 even when it examined nothing, so the exit code alone cannot
        # be trusted: check its own host counts before reporting "no open ports".
        counts = self._host_counts(root)
        if counts is not None:
            up, total = counts
            if total == 0:
                raise ScanError(
                    f"nmap scanned 0 hosts for {asked}",
                    plugin=self.name,
                    stderr=stderr,
                    output=raw,
                    no_response=True,
                )
            if up == 0:
                raise ScanError(
                    f"no host responded for {asked} ({total} probed): "
                    "down, or blocking nmap's host discovery",
                    plugin=self.name,
                    stderr=stderr,
                    output=raw,
                    no_response=True,
                )
        return ScanResult(assets=self._assets(root, hostname=target.hostname), raw=[raw])

    def _raw(self, command: list[str], stdout: str, stderr: str) -> RawOutput:
        return RawOutput(
            plugin=self.name,
            format="nmap-xml",
            command=tuple(command),
            content=stdout,
            stderr=stderr.strip(),
        )

    @staticmethod
    def _host_counts(root: ET.Element) -> tuple[int, int] | None:
        """Return nmap's own `(hosts up, hosts total)`, or None if it did not say."""
        hosts = root.find("runstats/hosts")
        if hosts is None:
            return None
        try:
            return int(hosts.get("up", "")), int(hosts.get("total", ""))
        except ValueError:
            return None

    @staticmethod
    def parse_xml(xml: str, hostname: str | None = None) -> list[Asset]:
        """Parse nmap `-oX` output into one `Asset` per host that is up.

        `hostname` is the name the user asked to scan, if any: nmap was given its
        addresses, so the output no longer says which name they belong to.
        """
        return NmapPlugin._assets(ET.fromstring(xml), hostname=hostname)

    @staticmethod
    def _assets(root: ET.Element, hostname: str | None = None) -> list[Asset]:
        assets: list[Asset] = []
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue  # with -v nmap also lists the hosts that did not answer
            ip = NmapPlugin._ip(host)
            if ip is None:
                continue  # no network address to attribute the result to
            assets.append(
                Asset(
                    # Name the asset the way the user asked for it; in an IP or
                    # range scan, the IP is the name. Reverse-DNS (PTR) names are
                    # not used: whoever owns the IP controls them.
                    host=hostname or ip,
                    ip=ip,
                    # A live host with nothing open is still a result worth keeping.
                    services=NmapPlugin._services(host),
                    route=NmapPlugin._route(host),
                )
            )
        return assets

    @staticmethod
    def _route(host: ET.Element) -> list[Hop]:
        """The `<trace>` of one `<host>`: the routers between the scanner and it.

        nmap leaves out the hops that never answered (so TTLs can have gaps) and writes
        `rtt="--"` for a hop it did not time for this host (one it shares with a host
        traced before).
        """
        trace = host.find("trace")
        if trace is None:
            return []
        hops: dict[int, Hop] = {}
        for hop in trace.findall("hop"):
            try:
                ttl = int(hop.get("ttl", ""))
            except ValueError:
                continue  # a hop without a distance cannot be placed on the path
            if ttl < 1:
                continue
            hops[ttl] = Hop(
                ttl=ttl,
                ip=hop.get("ipaddr") or None,
                rtt_ms=_rtt(hop.get("rtt")),
                name=hop.get("host") or None,
            )
        return [hops[ttl] for ttl in sorted(hops)]

    @staticmethod
    def _ip(host: ET.Element) -> str | None:
        """The host's IPv4/IPv6 address (nmap may also list its MAC address)."""
        for address in host.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6"):
                return address.get("addr")
        return None

    @staticmethod
    def _services(host: ET.Element) -> list[Service]:
        """The open ports of one `<host>` element."""
        services: list[Service] = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                svc_el = port.find("service")
                cpe = None
                name = product = version = banner = None
                if svc_el is not None:
                    name = svc_el.get("name")
                    product = svc_el.get("product")
                    version = svc_el.get("version")
                    cpe_el = svc_el.find("cpe")
                    cpe = cpe_el.text if cpe_el is not None else None
                    banner = (
                        " ".join(p for p in (product, version, svc_el.get("extrainfo")) if p)
                        or None
                    )
                services.append(
                    Service(
                        port=int(port.get("portid", "0")),
                        protocol=port.get("protocol", "tcp"),
                        state=state,
                        name=name,
                        product=product,
                        version=version,
                        cpe=cpe,
                        banner=banner,
                    )
                )
        return services


def _rtt(value: str | None) -> float | None:
    """A hop's round-trip time in ms; None for "--", missing or unreadable."""
    try:
        rtt = float(value or "")
    except ValueError:
        return None
    return rtt if rtt >= 0 else None


def _text(output: bytes | str | None) -> str:
    """Output captured by a timed-out run: always bytes, whatever `encoding` said."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def _version(address: str) -> int:
    """4 or 6, for an address or a range."""
    return ipaddress.ip_network(address, strict=False).version


def _by_family(target: ScanTarget) -> list[ScanTarget]:
    """`target` split into an IPv4 part and an IPv6 part (whichever exist)."""
    parts = []
    for version in (4, 6):
        addresses = tuple(a for a in target.addresses if _version(a) == version)
        if addresses:
            exclude = tuple(e for e in target.exclude if _version(e) == version)
            parts.append(replace(target, addresses=addresses, exclude=exclude))
    return parts
