"""Authenticated check: installed Debian packages vs the Debian Security Tracker.

For hosts the operator holds SSH credentials for, ZuesScan logs in, reads
`/etc/os-release` and the installed packages (`dpkg-query`), and compares every source
package with the tracker data in the CVE cache (`zues cve sync --debian <release>`).

Why it matters (G10): a banner says "OpenSSH 9.2p1"; Debian ships fixes as backports
without changing that number. Only the package version tells whether the fix is in.
So this check also *clears* CVEs: when the installed package carries the fix, the
version-based guesses for the same CVE on that host are withdrawn (see the
orchestrator).

Safety, because these are real credentials on real machines:

* key-based only (`BatchMode=yes`): never a password, never a prompt;
* the host key must already be known (`StrictHostKeyChecking=yes` with a dedicated
  known_hosts file): no trust-on-first-use, so a spoofed machine gets nothing;
* the remote command is fixed text (`debian.REMOTE_COMMAND`), read-only, no sudo;
* only addresses the scan found with SSH open, inside the credential's networks.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from zues_scan import debian
from zues_scan.cve.cache import CveCache
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.schema import Asset, Confidence, Finding, RawOutput, ScanTarget, Severity
from zues_scan.scope import Activity

_URGENCY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unimportant": Severity.INFO,
}


class CredentialError(Exception):
    """The credentials file cannot be used."""


@dataclass(frozen=True, slots=True)
class SshCredential:
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    user: str
    key: Path
    known_hosts: Path
    port: int = 22

    def covers(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(address in net for net in self.networks if net.version == address.version)


def load_credentials(path: str | Path) -> list[SshCredential]:
    """Read `[[ssh]]` entries from a TOML file. Passwords are not accepted."""
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise CredentialError(f"credentials file not found: {path}") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CredentialError(f"cannot read credentials file {path}: {exc}") from None
    entries = data.get("ssh", [])
    if not isinstance(entries, list) or not entries:
        raise CredentialError(f"{path}: no [[ssh]] entry")
    result = []
    for i, entry in enumerate(entries, start=1):
        where = f"{path}: [[ssh]] #{i}"
        unknown = set(entry) - {"hosts", "user", "key", "known_hosts", "port"}
        if "password" in entry:
            raise CredentialError(f"{where}: passwords are not supported; use an SSH key")
        if unknown:
            raise CredentialError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
        try:
            networks = tuple(ipaddress.ip_network(h, strict=False) for h in entry["hosts"])
            user, key, known = str(entry["user"]), entry["key"], entry["known_hosts"]
            port = int(entry.get("port", 22))
        except KeyError as exc:
            raise CredentialError(f"{where}: missing {exc}") from None
        except (ValueError, TypeError) as exc:
            raise CredentialError(f"{where}: {exc}") from None
        if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", user):
            raise CredentialError(f"{where}: invalid user name {user!r}")
        key_path, known_path = Path(key).expanduser(), Path(known).expanduser()
        for label, file in (("key", key_path), ("known_hosts", known_path)):
            if not file.is_file():
                raise CredentialError(f"{where}: {label} file not found: {file}")
        result.append(SshCredential(networks, user, key_path, known_path, port))
    return result


class SshPackagesPlugin:
    """Check plugin: logs in with SSH and compares installed packages with the tracker."""

    name = "ssh-packages"
    activity = Activity.SCAN  # logs in read-only

    def __init__(
        self, credentials: list[SshCredential], cache: CveCache, timeout: int = 120
    ) -> None:
        self.credentials = credentials
        self.cache = cache
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which("ssh") is not None

    def version(self) -> str | None:
        try:
            proc = subprocess.run(
                ["ssh", "-V"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r"OpenSSH\S*?_(\S+?),", proc.stderr + proc.stdout)
        return match.group(1) if match else None

    def command(self, credential: SshCredential, ip: str) -> list[str]:
        return [
            "ssh",
            "-i",
            str(credential.key),
            "-p",
            str(credential.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={credential.known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=10",
            "--",
            f"{credential.user}@{ip}",
            debian.REMOTE_COMMAND,
        ]

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        result = ScanResult()
        for asset in assets:
            if not asset.ip or not any(s.name == "ssh" or s.port == 22 for s in asset.services):
                continue
            credential = next((c for c in self.credentials if c.covers(asset.ip)), None)
            if credential is None:
                continue
            raw, output = self._login(credential, asset.ip)
            result.raw.append(raw)
            if output is None:
                result.notes.append(
                    f"{asset.ip}: login failed, no package check ({raw.stderr[:200]})"
                )
                continue
            found = self.assess(asset.ip, output)
            result.notes.extend(found.notes)
            result.assets.extend(found.assets)
            for ip, cves in found.cleared.items():
                result.cleared.setdefault(ip, set()).update(cves)
        return result

    def _login(self, credential: SshCredential, ip: str) -> tuple[RawOutput, str | None]:
        command = self.command(credential, ip)
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"ssh to {ip} timed out", plugin=self.name) from exc
        except OSError as exc:
            raise ScanError(f"could not start ssh: {exc}", plugin=self.name) from exc
        raw = RawOutput(
            plugin=self.name,
            format="os-release+dpkg",
            command=tuple(command),
            content=proc.stdout,
            stderr=proc.stderr.strip(),
        )
        # 255: ssh itself failed (refused, host key unknown, key rejected).
        return raw, (proc.stdout if proc.returncode == 0 else None)

    def assess(self, ip: str, output: str) -> ScanResult:
        """Findings (and cleared CVEs) for one host, from what it answered."""
        result = ScanResult()
        try:
            os_release, packages = debian.parse_remote(output)
        except ValueError as exc:
            result.notes.append(f"{ip}: {exc}")
            return result
        if os_release.id != "debian" or not os_release.codename:
            result.notes.append(
                f"{ip}: {os_release.pretty or 'unknown OS'}: only Debian is assessed"
            )
            return result
        sources: dict[str, str] = {}
        for p in packages:
            sources.setdefault(p.source, p.source_version)
        entries = self.cache.tracker_entries(os_release.codename, set(sources))
        if not entries and sources:
            result.notes.append(
                f"{ip}: no tracker data for Debian {os_release.codename}: "
                f"run zues cve sync --debian {os_release.codename}"
            )
            return result
        asset = Asset(host=ip, ip=ip)
        cleared: set[str] = set()
        affected: dict[str, list[tuple[debian.TrackerEntry, str]]] = defaultdict(list)
        for entry in entries:
            why = debian.verdict(sources[entry.source], entry)
            if why is None:
                cleared.add(entry.cve)
            else:
                affected[entry.cve].append((entry, why))
        for cve, hits in sorted(affected.items()):
            cleared.discard(cve)  # one package still affected keeps the CVE open
            entry, why = hits[0]
            installed = sources[entry.source]
            risk = self.cache.risk(cve)
            asset.findings.append(
                Finding(
                    asset=ip,
                    ip=ip,
                    title=f"{cve} in {entry.source} {installed}",
                    severity=_URGENCY.get(entry.urgency, Severity.MEDIUM),
                    cve=cve,
                    rule_id=f"debian:{entry.source}",
                    description=entry.description,
                    evidence=(
                        f"logged in over SSH: {os_release.pretty}; source package "
                        f"{entry.source} {installed} installed"
                        + "".join(f", also {e.source}" for e, _ in hits[1:])
                        + f". Debian security tracker ({entry.release}): {entry.status}, {why}."
                    ),
                    confidence=Confidence.FIRM,
                    **risk,
                )
            )
        result.assets.append(asset)
        result.cleared[ip] = cleared
        result.notes.append(
            f"{ip}: {len(packages)} packages checked on {os_release.pretty}: "
            f"{len(affected)} CVE(s) affect them"
        )
        return result
