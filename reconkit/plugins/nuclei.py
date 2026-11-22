"""nuclei adapter — template checks against the web services a scan found.

nuclei (ProjectDiscovery) sends requests described by community templates and reports
the ones whose response matches: a CVE that answers like the vulnerable version, an
exposed admin panel, a misconfiguration. Unlike a version match, a hit is an
*observation*, so its findings are stronger evidence (see `confidence` below).

It is a **check** plugin: it runs after the port scan, on what the scan found
(`check(plan, assets)`), never on targets of its own:

* targets are URLs built from the open HTTP(S) services, always with the **address**
  the scope guard approved (`http://10.0.0.5:8080`), never a name nuclei would resolve
  again;
* a virtual host (a name pointing at that address) is tested by sending its name in
  the `Host` header and TLS SNI — one nuclei run per name — so a site is checked as
  itself while the connection still goes to the approved address.

Safe defaults, because a scan must not harm or leak:

* `-ni`: no interactsh. Out-of-band checks would make targets call a public
  ProjectDiscovery server, sending engagement data outside.
* `-etags dos,fuzz,intrusive,bruteforce`: no template that floods, fuzzes or tries
  passwords; `-rl`: requests per second capped (the profile's max rate, else 50).
* `-duc`: no update check from inside a scan.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from reconkit.plugins.base import ScanError, ScanResult
from reconkit.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from reconkit.schema import Asset, Confidence, Finding, RawOutput, ScanTarget, Service, Severity

EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")
DEFAULT_RATE = 50

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_TLS_PORTS = {443, 8443, 9443, 4443}


def web_url(ip: str, service: Service) -> str | None:
    """The URL of an open HTTP(S) service, by address; None if it is not a web service."""
    name = (service.name or "").lower()
    if service.protocol != "tcp" or "http" not in name:
        return None
    tls = "https" in name or "ssl" in name or service.port in _TLS_PORTS
    host = f"[{ip}]" if ":" in ip else ip
    return f"{'https' if tls else 'http'}://{host}:{service.port}"


class NucleiPlugin:
    """Check plugin backed by the `nuclei` binary."""

    name = "nuclei"

    def __init__(self, profile: ScanProfile | None = None, timeout: int | None = None) -> None:
        self.profile = profile or BUILTIN[DEFAULT_PROFILE]
        self.timeout = timeout or self.profile.timeout
        self.rate = self.profile.max_rate or DEFAULT_RATE

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def version(self) -> str | None:
        try:
            proc = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r"Engine Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        return match.group(1) if match else None

    def command(self, vhost: str | None) -> list[str]:
        command = [
            "nuclei",
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-ni",
            "-etags",
            ",".join(EXCLUDED_TAGS),
            "-rl",
            str(self.rate),
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        if vhost:
            command += ["-H", f"Host: {vhost}", "-sni", vhost]
        return command

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        """Run nuclei on the web services of `assets`; their findings, as assets."""
        if not self.is_available():
            raise ScanError("nuclei is not installed or not on PATH", plugin=self.name)
        groups = self.targets(assets)
        result = ScanResult()
        if not groups:
            result.notes.append("no web service to check")
            return result
        found: dict[str, Asset] = {}
        for vhost, urls in groups.items():
            raw = self._run(vhost, urls)
            result.raw.append(raw)
            for ip, finding in self.parse_jsonl(raw.content, vhost):
                asset = found.setdefault(ip, Asset(host=ip, ip=ip))
                asset.findings.append(finding)
        # Tie each finding to the service the scan found on that port.
        services = {(a.ip, s.port, s.protocol): s for a in assets for s in a.services}
        for asset in found.values():
            for f in asset.findings:
                if f.service is not None:
                    f.service = services.get((asset.ip, f.service.port, "tcp"), f.service)
        result.assets = list(found.values())
        return result

    @staticmethod
    def targets(assets: list[Asset]) -> dict[str | None, list[str]]:
        """URLs to check, grouped by the virtual host name to send (None: by address)."""
        groups: dict[str | None, list[str]] = defaultdict(list)
        for asset in assets:
            if not asset.ip:
                continue
            urls = [u for u in (web_url(asset.ip, s) for s in asset.services) if u]
            vhosts: list[str | None] = list(asset.names) or [None]
            for vhost in vhosts:
                groups[vhost] += urls
        return {k: v for k, v in groups.items() if v}

    def _run(self, vhost: str | None, urls: list[str]) -> RawOutput:
        command = self.command(vhost)
        try:
            proc = subprocess.run(
                command,
                input="\n".join(urls) + "\n",
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"nuclei timed out after {self.timeout}s", plugin=self.name) from exc
        except subprocess.CalledProcessError as exc:
            raise ScanError(
                f"nuclei exited with code {exc.returncode}",
                plugin=self.name,
                stderr=(exc.stderr or "").strip() or None,
            ) from exc
        except OSError as exc:
            raise ScanError(f"could not start nuclei: {exc}", plugin=self.name) from exc
        # The URL list is part of what was run: keep it with the command.
        return RawOutput(
            plugin=self.name,
            format="nuclei-jsonl",
            command=(*command, "<", *urls),
            content=proc.stdout,
            stderr=proc.stderr.strip(),
        )

    @staticmethod
    def parse_jsonl(text: str, vhost: str | None = None) -> list[tuple[str, Finding]]:
        """(address, finding) for every match in nuclei's JSON lines output."""
        results: list[tuple[str, Finding]] = []
        for line in text.splitlines():
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(hit, dict) or "template-id" not in hit:
                continue
            parsed = _finding(hit, vhost)
            if parsed is not None:
                results.append(parsed)
        return results


def _finding(hit: dict[str, Any], vhost: str | None) -> tuple[str, Finding] | None:
    url = str(hit.get("matched-at") or hit.get("url") or hit.get("host") or "")
    parts = urlsplit(url if "://" in url else f"tcp://{url}")
    ip = str(hit.get("ip") or parts.hostname or "")
    if not ip:
        return None
    info = hit.get("info") or {}
    classification = info.get("classification") or {}
    template = str(hit["template-id"])
    cves = [str(c).upper() for c in classification.get("cve-id") or [] if c]
    port = _int(hit.get("port")) or parts.port
    evidence = f"nuclei template {template} matched at {url}"
    if hit.get("matcher-name"):
        evidence += f" (matcher {hit['matcher-name']})"
    extracted = [str(x) for x in hit.get("extracted-results") or []][:3]
    if extracted:
        evidence += f"; extracted: {', '.join(e[:120] for e in extracted)}"
    if vhost:
        evidence += f"; sent as virtual host {vhost}"
    finding = Finding(
        asset=ip,
        ip=ip,
        title=str(info.get("name") or template),
        severity=_SEVERITY.get(str(info.get("severity", "")).lower(), Severity.INFO),
        service=Service(port=port, name=parts.scheme or None) if port else None,
        cve=cves[0] if cves else None,
        description=str(info.get("description") or "").strip(),
        evidence=evidence,
        # The check name is the identity; a site on a shared address is its own target.
        rule_id=f"nuclei:{template}" + (f"@{vhost}" if vhost else ""),
        # A CVE template sends the request that exposes the flaw and checks the answer;
        # other templates mostly detect a product or an exposure.
        confidence=Confidence.CONFIRMED if template.upper().startswith("CVE-") else Confidence.FIRM,
        cvss_score=_float(classification.get("cvss-score")),
        cvss_vector=classification.get("cvss-metrics") or None,
        cwe=tuple(str(c).upper() for c in classification.get("cwe-id") or [] if c),
        epss=_float(classification.get("epss-score")),
    )
    return ip, finding


def _int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _float(value: object) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None
