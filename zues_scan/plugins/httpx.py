"""httpx adapter — what each web service is: status, title, server, technologies.

nmap names the web server ("Apache httpd 2.4.49"); what runs *behind* it — PHP 7.4,
WordPress, Grafana, jQuery — only shows in the HTTP answer. httpx (ProjectDiscovery)
fetches the root of every web service the scan found and recognises the technologies
with Wappalyzer's fingerprints, versions included where the answer gives them away.

- Which services: those nmap calls http/https (any name with "http"), and, when a port
  has no name (naabu without nmap), the usual web ports. httpx tries HTTPS, then HTTP.
- Always to the scanned address. Each web service is asked once by address (the
  server's default site), then once under every name of its host (the target's own name,
  names discovery found pointing at it) as the Host header — virtual hosts: one machine
  often serves other sites by name. The line `name,ip:port` makes httpx connect to that
  address and send `Host: name`; a name is never resolved again, so it cannot lead to an
  address the scope guard did not approve. At most `MAX_VHOSTS` such lines per check.
  The TLS SNI stays the address (httpx's `-sni` is one name for the whole run): a server
  that picks the site by SNI alone shows its default one.
- Plain GET of `/`, redirects not followed: activity `scan`, like nmap's own probes;
  rate capped by the profile's `check_rate` (default 50 requests/s).
- What it saw is attached to the service (`Service.web`); technologies with a version
  go to the CVE stage as software on that port (`zues_scan.cve.match.components`).

`check()` runs `httpx -l <inputs> -json ...`; `parse_jsonl()` reads its JSON lines as a
pure function. Titles and names come from the scanned machine: control characters are
removed and lengths capped here, and they are shown escaped everywhere.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from zues_scan import tools
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from zues_scan.schema import Asset, RawOutput, ScanTarget, Service, WebPage
from zues_scan.scope import Activity

WEB_PORTS = frozenset(
    {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
)
MAX_TEXT = 200  # title, server, one technology
MAX_VHOSTS = 200  # (name, web service) pairs asked by name in one check
# A DNS name as it may go on an input line: no comma, space or anything httpx would read
# as a URL, a port or another input. Lower case (as `names()` makes it).
_NAME = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}))*")
MAX_TECHNOLOGIES = 30
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


class HttpxPlugin:
    """Check plugin backed by the `httpx` binary (ProjectDiscovery's, not the Python one)."""

    name = "httpx"
    activity = Activity.SCAN  # a plain GET of `/`, as a browser would

    def __init__(self, profile: ScanProfile | None = None) -> None:
        self.profile = profile if profile is not None else BUILTIN[DEFAULT_PROFILE]
        self.rate = self.profile.check_rate or 50
        self.timeout = self.profile.timeout  # seconds for the whole check

    def is_available(self) -> bool:
        return tools.which("httpx") is not None

    def version(self) -> str | None:
        try:
            with tempfile.TemporaryDirectory(prefix="zues-httpx-") as home:
                proc = subprocess.run(
                    [tools.resolve("httpx"), "-version", "-duc"],
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                    env=_env(home),
                )
        except (OSError, subprocess.SubprocessError):
            return None
        # It prints e.g. "[INF] Current Version: v1.12.0" (on stderr).
        match = re.search(r"Current Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        return match.group(1) if match else None

    @staticmethod
    def inputs(assets: list[Asset]) -> list[str]:
        """httpx's input lines: `ip:port` of every web service found (IPv6 as
        `[ip]:port`), then `name,ip:port` for each name of its host, each once."""
        return plan_inputs(assets)[0]

    @staticmethod
    def names(asset: Asset) -> list[str]:
        """The names to ask this host's web services under: its own name and every name
        found pointing at it, those that are plain DNS names only."""
        found = dict.fromkeys(n.strip().lower().rstrip(".") for n in [asset.host, *asset.names])
        return [n for n in found if _is_name(n) and n != asset.ip]

    def command(self, inputs_file: str) -> list[str]:
        return [
            tools.resolve("httpx"),
            "-l",
            inputs_file,
            "-json",
            "-silent",
            "-nc",
            "-duc",
            "-sc",
            "-title",
            "-server",
            "-td",
            "-fr=false",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-rl",
            str(self.rate),
            "-t",
            str(min(self.rate, 25)),
        ]

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        if not self.is_available():
            raise ScanError("httpx is not installed or not on PATH", plugin=self.name)
        inputs, left_out = plan_inputs(assets)
        result = ScanResult()
        if not inputs:
            result.notes.append("no web service found to look at")
            return result
        if left_out:
            result.notes.append(
                f"asked {MAX_VHOSTS} site(s) by name; {left_out} more name(s) left out"
            )
        with tempfile.TemporaryDirectory(prefix="zues-httpx-") as home:
            inputs_file = os.path.join(home, "inputs.txt")
            Path(inputs_file).write_text("\n".join(inputs) + "\n", encoding="utf-8")
            command = self.command(inputs_file)
            try:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout,
                    check=True,
                    env=_env(home),
                )
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                stdout, stderr = _text(exc.stdout), _text(exc.stderr)
                result.incomplete = True
                result.notes.append(f"stopped after {self.timeout}s: some services not looked at")
            except subprocess.CalledProcessError as exc:
                raise ScanError(
                    f"httpx exited with code {exc.returncode}",
                    plugin=self.name,
                    stderr=(exc.stderr or "").strip() or None,
                ) from exc
            except OSError as exc:
                raise ScanError(f"could not start httpx: {exc}", plugin=self.name) from exc
        result.raw.append(
            RawOutput(
                plugin=self.name,
                format="httpx-jsonl",
                command=tuple(command),
                content=stdout,
                stderr=stderr.strip(),
            )
        )
        pages, skipped = parse_jsonl(stdout)
        by_service: dict[tuple[str, int], tuple[WebPage | None, list[WebPage]]] = {}
        for (ip, port, name), page in sorted(pages.items(), key=lambda kv: _order(kv[0])):
            default, named = by_service.setdefault((ip, port), (None, []))
            if name is None:
                by_service[(ip, port)] = (page, named)
            else:
                named.append(page)
        by_ip: dict[str, Asset] = {}
        for (ip, port), (default, named) in by_service.items():
            asset = by_ip.setdefault(ip, Asset(host=ip, ip=ip))
            asset.services.append(Service(port=port, web=default, vhosts=tuple(named)))
        result.assets = list(by_ip.values())
        by_address = sum(1 for _, _, name in pages if name is None)
        asked = sum(1 for line in inputs if "," not in line)
        result.notes.append(f"{by_address} of {asked} web service(s) answered")
        if len(inputs) > asked:
            named_count = len(pages) - by_address
            result.notes.append(f"{named_count} of {len(inputs) - asked} site(s) by name answered")
        if skipped:
            result.notes.append(f"ignored {skipped} line(s) of httpx output it could not read")
        return result


def plan_inputs(assets: list[Asset]) -> tuple[list[str], int]:
    """(httpx's input lines, names left out over `MAX_VHOSTS`): every web service by
    address first, then by name, so that a cap never costs a service its default site."""
    by_address: dict[str, None] = {}
    by_name: dict[str, None] = {}
    for asset in assets:
        if not asset.ip:
            continue
        host = f"[{asset.ip}]" if ":" in asset.ip else asset.ip
        names = HttpxPlugin.names(asset)
        for service in asset.services:
            if service.protocol == "tcp" and _is_web(service):
                by_address[f"{host}:{service.port}"] = None
                for name in names:
                    by_name[f"{name},{host}:{service.port}"] = None
    named = list(by_name)
    return [*by_address, *named[:MAX_VHOSTS]], max(0, len(named) - MAX_VHOSTS)


def parse_jsonl(text: str) -> tuple[dict[tuple[str, int, str | None], WebPage], int]:
    """({(ip, port, name or None): what was seen}, unreadable lines) from httpx's JSON
    lines; the name is the one sent as Host (input `name,ip:port`), None by address."""
    pages: dict[tuple[str, int, str | None], WebPage] = {}
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record: dict[str, Any] = json.loads(line)
            if record.get("failed"):
                continue
            name, comma, address = str(record["input"]).rpartition(",")
            if comma and not _is_name(name):
                raise ValueError(f"not a name: {name!r}")
            host, _, port = address.rpartition(":")
            ip = str(ipaddress.ip_address(host.strip("[]")))
            status = record.get("status_code")
            page = WebPage(
                url=_clean(str(record["url"])) or "",
                status=int(status) if status is not None else None,
                title=_clean(record.get("title")),
                server=_clean(record.get("webserver")),
                technologies=tuple(
                    t
                    for t in (_clean(t) for t in (record.get("tech") or [])[:MAX_TECHNOLOGIES])
                    if t
                ),
                host=name or None,
            )
            pages[(ip, int(port), name or None)] = page
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            skipped += 1
    return pages, skipped


def _is_name(text: str) -> bool:
    """A DNS name (not an address) that is safe on an httpx input line."""
    if len(text) > 253 or not _NAME.fullmatch(text):
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return True
    return False


def _order(key: tuple[str, int, str | None]) -> tuple[str, int, str]:
    ip, port, name = key
    return ip, port, name or ""  # by address first ("" sorts before any name)


def _is_web(service: Service) -> bool:
    if service.name:
        return "http" in service.name.lower()
    return service.port in WEB_PORTS


def _clean(value: object) -> str | None:
    """Text from the scanned machine: no control or direction characters, capped."""
    if value is None:
        return None
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text[:MAX_TEXT] or None


def _env(home: str) -> dict[str, str]:
    return {**os.environ, "HOME": home, "USERPROFILE": home}


def _text(output: bytes | str | None) -> str:
    if output is None:
        return ""
    return output.decode("utf-8", "replace") if isinstance(output, bytes) else output
