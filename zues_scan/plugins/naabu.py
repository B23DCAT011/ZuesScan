"""naabu adapter — fast port discovery, then nmap only where something is open.

naabu (ProjectDiscovery) finds open ports with a TCP connect scan — no raw sockets, no
Npcap, no root — at a fixed, configurable rate. Three steps:

1. nmap pings the addresses (`-sn`) to find the hosts that are up. naabu cannot do that
   itself without root ("sudo access required to perform host discovery"), and without
   it every port of every address is tried: a full-port scan of a mostly empty /24 is
   15.7 million connections, hours at naabu's 1,000 per second. With `assume_up` in the
   profile (or without nmap) every address is scanned, as asked.
2. naabu scans the ports of the hosts that are up.
3. nmap (`-sV`, plus traceroute if the profile asks) identifies the services, only on
   the hosts with open ports and only on those ports. The result is the same kind of
   asset nmap gives (service names and versions, so the CVE stage works).

Measured on the lab (DMZ /24, 3 hosts up): see docs; naabu pays off on many hosts and
few ports (top 100 / 1,000 over large ranges, high-latency links), not on a full-port
scan of a fast LAN, where nmap's adaptive SYN scan is already quick.

From the profile: `ports` (else `top_ports`: naabu knows only its 100 and 1,000 most
common ports and "full", so the nearest list at least as large is used), `max_rate`
(packets per second, default 1000), `max_retries`, `timeout`. Without nmap, or with
`version_detection = false`, the run has ports only (noted: no CVE matching then).

`scan()` runs `naabu -host <addresses> -eh <excluded> -s c ... -json` and reads its
JSON lines (`{"ip": "10.0.0.5", "port": 80, "protocol": "tcp"}`); `parse_jsonl()` does
the reading as a pure function. Out of time, the ports found so far are kept and the run
is marked incomplete.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from zues_scan import tools
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from zues_scan.schema import Asset, RawOutput, ScanTarget, Service
from zues_scan.scope import Activity

NAABU_TOP = (100, 1000)  # the top-port lists naabu has, besides "full"


class NaabuPlugin:
    """Scanner plugin backed by the `naabu` binary (and nmap for the services)."""

    name = "naabu"
    activity = Activity.SCAN  # finds open ports, like nmap

    def __init__(
        self,
        profile: ScanProfile | None = None,
        nmap: Callable[..., Any] = NmapPlugin,
    ) -> None:
        self.profile = profile if profile is not None else BUILTIN[DEFAULT_PROFILE]
        self.nmap = nmap  # builds an nmap for a profile (ping_only=True: discovery)

    def is_available(self) -> bool:
        return tools.which("naabu") is not None

    def _identifier(self) -> Any | None:
        """The nmap that will identify services, if the profile wants it and nmap is here."""
        if not self.profile.version_detection:
            return None
        nmap = self.nmap(self.profile)
        return nmap if nmap.is_available() else None

    def version(self) -> str | None:
        try:
            with tempfile.TemporaryDirectory(prefix="zues-naabu-") as home:
                proc = subprocess.run(
                    [tools.resolve("naabu"), "-version", "-duc"],
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                    env=_env(home),
                )
        except (OSError, subprocess.SubprocessError):
            return None
        # It prints e.g. "[INF] Current Version: 2.7.0" (on stderr).
        match = re.search(r"Current Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        if match is None:
            return None
        nmap = self._identifier()
        nmap_version = nmap.version() if nmap is not None else None
        return (
            f"{match.group(1)} (services: nmap {nmap_version})" if nmap_version else match.group(1)
        )

    def ports(self) -> tuple[list[str], str | None]:
        """naabu's port options for the profile, and a note if they differ from nmap's."""
        ports, top = self.profile.ports, self.profile.top_ports
        if ports == "-":
            return ["-tp", "full"], None
        if ports is not None:
            return ["-p", ports], None
        wanted = top or 1000  # nmap's default is its 1,000 most common ports
        size = next((n for n in NAABU_TOP if n >= wanted), None)
        if size is None:
            return ["-tp", "full"], f"top {wanted} ports asked: naabu scanned all ports"
        note = None if size == wanted else f"top {wanted} ports asked: naabu scanned its top {size}"
        return ["-tp", str(size)], note

    def command(self, target: ScanTarget) -> tuple[list[str], str | None]:
        port_args, note = self.ports()
        command = [
            tools.resolve("naabu"),
            "-host",
            ",".join(target.addresses),
            *(["-eh", ",".join(target.exclude)] if target.exclude else []),
            "-s",
            "c",  # connect scan: no raw sockets needed
            *port_args,
            "-rate",
            str(self.profile.max_rate or 1000),
            *(["-retries", str(self.profile.max_retries)] if self.profile.max_retries else []),
            "-json",
            "-silent",
            "-nc",
            "-duc",
        ]
        return command, note

    def _live(self, target: ScanTarget, result: ScanResult) -> ScanTarget | None:
        """`target` narrowed to the hosts nmap finds up (None: nothing answered)."""
        if self.profile.assume_up:
            return target  # every address, as the profile asks
        pinger = self.nmap(self.profile, ping_only=True)
        if not pinger.is_available():
            result.notes.append(
                "no host discovery (no nmap): every port of every address is tried, "
                "slow on a sparse range"
            )
            return target
        try:
            pinged = pinger.scan(target)
        except ScanError as exc:
            if exc.output is not None:
                result.raw.append(exc.output)
            if exc.no_response:
                result.notes.append(f"host discovery (nmap -sn): {exc}")
                return None
            raise ScanError(f"host discovery (nmap -sn) failed: {exc}", plugin=self.name) from exc
        result.raw.extend(pinged.raw)
        hosts = sorted({a.ip for a in pinged.assets if a.ip}, key=ipaddress.ip_address)
        result.notes.append(f"host discovery (nmap -sn): {len(hosts)} host(s) up")
        return replace(target, addresses=tuple(hosts)) if hosts else None

    def scan(self, target: ScanTarget) -> ScanResult:
        if not self.is_available():
            raise ScanError("naabu is not installed or not on PATH", plugin=self.name)
        result = ScanResult()
        live = self._live(target, result)
        if live is None:
            return result
        # The hosts nmap saw up: one with nothing open is still a result, as with nmap.
        up = list(live.addresses) if live is not target else []
        target = live
        command, note = self.command(target)
        if note:
            result.notes.append(note)
        try:
            with tempfile.TemporaryDirectory(prefix="zues-naabu-") as home:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.profile.timeout,
                    check=True,
                    env=_env(home),
                )
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = _text(exc.stdout), _text(exc.stderr)
            result.incomplete = True
            result.notes.append(
                f"stopped after {self.profile.timeout}s: the ports found so far are kept"
            )
        except subprocess.CalledProcessError as exc:
            raise ScanError(
                f"naabu exited with code {exc.returncode}",
                plugin=self.name,
                stderr=(exc.stderr or "").strip() or None,
            ) from exc
        except OSError as exc:
            raise ScanError(f"could not start naabu: {exc}", plugin=self.name) from exc
        result.raw.append(
            RawOutput(
                plugin=self.name,
                format="naabu-jsonl",
                command=tuple(command),
                content=stdout,
                stderr=stderr.strip(),
            )
        )
        found, skipped = parse_jsonl(stdout)
        if skipped:
            result.notes.append(f"ignored {skipped} line(s) of naabu output it could not read")
        open_ports = sum(len(p) for p in found.values())
        result.notes.append(f"{open_ports} open port(s) on {len(found)} host(s)")
        if not found:
            result.assets = [Asset(host=ip, ip=ip) for ip in up]
            return result
        services: dict[str, Asset] = {}
        nmap = self._identifier()
        if nmap is None:
            why = "version_detection is off" if not self.profile.version_detection else "no nmap"
            result.notes.append(f"ports only ({why}): no service names or versions, no CVE match")
        else:
            services = self._identify(nmap, target, found, result)
        for ip in sorted(found, key=ipaddress.ip_address):
            asset = services.get(ip) or Asset(host=ip, ip=ip)
            known = {(s.port, s.protocol) for s in asset.services}
            for port in sorted(found[ip]):
                if (port, "tcp") not in known:
                    asset.services.append(Service(port=port))
            asset.services.sort(key=lambda s: (s.port, s.protocol))
            result.assets.append(asset)
        result.assets += [Asset(host=ip, ip=ip) for ip in up if ip not in found]
        result.assets.sort(key=lambda a: ipaddress.ip_address(a.ip or a.host))
        return result

    def _identify(
        self, nmap_for: Any, target: ScanTarget, found: dict[str, set[int]], result: ScanResult
    ) -> dict[str, Asset]:
        """nmap on the open ports of the hosts naabu found: {ip: asset with services}."""
        ports = ",".join(str(p) for p in sorted(set().union(*found.values())))
        hosts = tuple(sorted(found, key=ipaddress.ip_address))
        profile = replace(self.profile, ports=ports, top_ports=None, assume_up=True)
        nmap = self.nmap(profile)
        try:
            identified = nmap.scan(replace(target, addresses=hosts))
        except ScanError as exc:
            # naabu's ports are still true: keep them, say what is missing.
            result.incomplete = True
            result.notes.append(f"service detection (nmap) failed, ports only: {exc}")
            if exc.output is not None:
                result.raw.append(exc.output)
            return {}
        result.raw.extend(identified.raw)
        result.notes.extend(f"nmap: {n}" for n in identified.notes)
        return {a.ip: a for a in identified.assets if a.ip is not None}


def parse_jsonl(text: str) -> tuple[dict[str, set[int]], int]:
    """({ip: open TCP ports}, unreadable lines) from naabu's JSON lines."""
    found: dict[str, set[int]] = {}
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            ip = str(ipaddress.ip_address(record["ip"]))
            port = int(record["port"])
            protocol = str(record.get("protocol") or "tcp")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            skipped += 1
            continue
        if not 1 <= port <= 65535 or protocol != "tcp":
            skipped += 1
            continue
        found.setdefault(ip, set()).add(port)
    return found, skipped


def _env(home: str) -> dict[str, str]:
    return {**os.environ, "HOME": home, "USERPROFILE": home}


def _text(output: bytes | str | None) -> str:
    if output is None:
        return ""
    return output.decode("utf-8", "replace") if isinstance(output, bytes) else output
