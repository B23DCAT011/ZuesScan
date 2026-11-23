"""nuclei adapter — template checks against the services a scan found.

nuclei (ProjectDiscovery) sends requests described by community templates and reports
the ones whose response matches: a CVE that answers like the vulnerable version, an
exposed admin panel, a misconfiguration. Unlike a version match, a hit is an
*observation*, so its findings are stronger evidence (see `confidence` below).

It is a **check** plugin: it runs after the port scan, on what the scan found
(`check(plan, assets)`), never on targets of its own:

* web services become URLs built with the **address** the scope guard approved
  (`http://10.0.0.5:8080`), never a name nuclei would resolve again;
* other open TCP services become `address:port`, checked in a run of their own with
  only the protocols that apply (`-pt javascript,tcp,ssl`: an SSH server vulnerable to
  Terrapin, a Redis without a password). Measured on the lab: the same SSH port fed to
  every template took 147 s for the same single match that 163 network templates found
  at once - most templates are HTTP ones, which an SSH port can only time out on;
* a virtual host (a name pointing at that address) is tested by sending its name in
  the `Host` header and TLS SNI — one nuclei run per name — so a site is checked as
  itself while the connection still goes to the approved address.

Safe defaults, because a scan must not harm or leak:

* `-ni`: no interactsh. Out-of-band checks would make targets call a public
  ProjectDiscovery server, sending engagement data outside.
* `-etags dos,fuzz,intrusive,bruteforce`: no template that floods, fuzzes or tries
  passwords; `-rl`: requests per second capped (the profile's max rate, else 50).
  Code, headless, file and DAST templates are never enabled (`-code`, `-headless`,
  `-lfa`, `-dast` are not passed).
* `-dut`: only templates whose signature checks out (ProjectDiscovery signs its
  templates): an edited or planted template does not run.
* `-es info`: no informational templates (technology detection, missing headers):
  ReconKit records weaknesses, not inventory trivia.
* `-duc`: no update check from inside a scan.

Templates: given a directory (`templates`, e.g. the copy pinned in the Docker image),
nuclei runs exactly those, offline, from a fresh configuration directory of its own for
each run — nothing carries over between scans, and the templates' version (from a
`.reconkit-version` file next to them) is recorded with the run. Without one, nuclei
uses its own installation and configuration, as on a workstation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from reconkit.plugins.base import ScanError, ScanResult
from reconkit.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from reconkit.schema import Asset, Confidence, Finding, RawOutput, ScanTarget, Service, Severity

EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")
EXCLUDED_SEVERITIES = ("info",)
NETWORK_PROTOCOLS = ("javascript", "tcp", "ssl")  # nuclei's -pt names for non-web checks
DEFAULT_RATE = 50
# Where the Docker image (or an administrator) says the pinned templates are.
TEMPLATES_ENV = "RECONKIT_NUCLEI_TEMPLATES"
VERSION_FILE = ".reconkit-version"

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_TLS_PORTS = {443, 8443, 9443, 4443}


def default_templates() -> str | None:
    """The templates directory named by the environment, if any."""
    return os.environ.get(TEMPLATES_ENV) or None


def templates_version(directory: str) -> str | None:
    """The version recorded next to a templates directory (e.g. "10.5.2")."""
    try:
        text = Path(directory, VERSION_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text.lstrip("v") or None


def web_url(ip: str, service: Service) -> str | None:
    """The URL of an open HTTP(S) service, by address; None if it is not a web service."""
    name = (service.name or "").lower()
    if service.protocol != "tcp" or "http" not in name:
        return None
    tls = "https" in name or "ssl" in name or service.port in _TLS_PORTS
    host = f"[{ip}]" if ":" in ip else ip
    return f"{'https' if tls else 'http'}://{host}:{service.port}"


def network_target(ip: str, service: Service) -> str | None:
    """`address:port` of an open TCP service that is not a web service."""
    if service.protocol != "tcp" or web_url(ip, service) is not None:
        return None
    if service.state not in (None, "open"):
        return None
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{service.port}"


class NucleiPlugin:
    """Check plugin backed by the `nuclei` binary."""

    name = "nuclei"

    def __init__(
        self,
        profile: ScanProfile | None = None,
        timeout: int | None = None,
        templates: str | None = None,
    ) -> None:
        self.profile = profile or BUILTIN[DEFAULT_PROFILE]
        self.timeout = timeout or self.profile.timeout  # for all of this check's runs
        self.rate = self.profile.max_rate or DEFAULT_RATE
        self.templates = templates
        self.clock: Callable[[], float] = time.monotonic  # replaceable in tests

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def version(self) -> str | None:
        """The engine's version, and the templates' when they are pinned:
        "3.11.1 (templates 10.5.2)". Two runs are comparable only with both."""
        try:
            with tempfile.TemporaryDirectory(prefix="reconkit-nuclei-") as home:
                proc = subprocess.run(
                    ["nuclei", "-version"],
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                    env=self._env(home) if self.templates is not None else None,
                )
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r"Engine Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        if match is None:
            return None
        if self.templates is None:
            return match.group(1)
        return f"{match.group(1)} (templates {templates_version(self.templates) or 'unknown'})"

    def command(self, vhost: str | None, network: bool = False) -> list[str]:
        command = [
            "nuclei",
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-ni",
            "-dut",
            "-etags",
            ",".join(EXCLUDED_TAGS),
            "-es",
            ",".join(EXCLUDED_SEVERITIES),
            "-rl",
            str(self.rate),
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        if self.templates is not None:
            command += ["-t", self.templates]
        if network:
            command += ["-pt", ",".join(NETWORK_PROTOCOLS)]
        if vhost:
            command += ["-H", f"Host: {vhost}", "-sni", vhost]
        return command

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        """Run nuclei on the services of `assets`; their findings, as assets.

        The whole check shares one time budget (`timeout`). If it runs out, the findings
        so far are kept and the result is marked incomplete; the remaining runs (other
        virtual hosts) are skipped and listed.
        """
        if not self.is_available():
            raise ScanError("nuclei is not installed or not on PATH", plugin=self.name)
        if self.templates is not None and not Path(self.templates).is_dir():
            raise ScanError(f"nuclei templates not found: {self.templates}", plugin=self.name)
        groups = self.targets(assets)
        result = ScanResult()
        if not groups:
            result.notes.append("no service to check")
            return result
        found: dict[str, Asset] = {}
        deadline = self.clock() + self.timeout
        runs = [
            (vhost, part, network)
            for vhost, inputs in groups.items()
            for network, part in (
                (False, [i for i in inputs if "://" in i]),
                (True, [i for i in inputs if "://" not in i]),
            )
            if part
        ]
        for vhost, inputs, network in runs:
            left = int(deadline - self.clock())
            if left < 1:
                result.incomplete = True
                result.notes.append(f"not checked, out of time: {_label(vhost, inputs)}")
                continue
            raw, finished = self._run(self.command(vhost, network), inputs, left)
            result.raw.append(raw)
            if not finished:
                result.incomplete = True
                result.notes.append(
                    f"stopped after its time limit ({self.timeout}s) while checking "
                    f"{_label(vhost, inputs)}: findings so far are kept"
                )
            for ip, finding in self.parse_jsonl(raw.content, vhost if not network else None):
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
        """Inputs to check, grouped by the virtual host name to send (None: by address).

        Web services are checked once per name pointing at the host (as that site);
        other services have no notion of a site and are checked once, by address.
        """
        groups: dict[str | None, list[str]] = defaultdict(list)
        for asset in assets:
            if not asset.ip:
                continue
            urls = [u for u in (web_url(asset.ip, s) for s in asset.services) if u]
            vhosts: list[str | None] = list(asset.names) or [None]
            for vhost in vhosts:
                groups[vhost] += urls
            groups[None] += [t for t in (network_target(asset.ip, s) for s in asset.services) if t]
        return {k: v for k, v in groups.items() if v}

    def _env(self, home: str | None) -> dict[str, str] | None:
        """nuclei's environment: its own fresh home and configuration when templates are
        pinned (nothing read from or left in the user's), else the caller's."""
        if home is None:
            return None
        return {
            **os.environ,
            "HOME": home,
            "USERPROFILE": home,  # Windows
            "NUCLEI_CONFIG_DIR": str(Path(home, "config")),
        }

    def _run(self, command: list[str], inputs: list[str], timeout: int) -> tuple[RawOutput, bool]:
        """One nuclei run; its output and whether it finished in time."""
        with tempfile.TemporaryDirectory(prefix="reconkit-nuclei-") as home:
            env = None
            if self.templates is not None:
                config = Path(home, "config")
                config.mkdir()
                # The templates' default exclusions (noisy or risky ones), as nuclei would
                # install them next to its own configuration.
                ignore = Path(self.templates, ".nuclei-ignore")
                if ignore.is_file():
                    shutil.copyfile(ignore, config / ".nuclei-ignore")
                env = self._env(home)
            finished = True
            try:
                proc = subprocess.run(
                    command,
                    input="\n".join(inputs) + "\n",
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=True,
                    env=env,
                )
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                # nuclei prints each match as it finds it: what came before the time
                # limit is real, only incomplete.
                finished = False
                stdout, stderr = _text(exc.stdout), _text(exc.stderr)
            except subprocess.CalledProcessError as exc:
                raise ScanError(
                    f"nuclei exited with code {exc.returncode}",
                    plugin=self.name,
                    stderr=(exc.stderr or "").strip() or None,
                ) from exc
            except OSError as exc:
                raise ScanError(f"could not start nuclei: {exc}", plugin=self.name) from exc
        # The input list is part of what was run: keep it with the command.
        raw = RawOutput(
            plugin=self.name,
            format="nuclei-jsonl",
            command=(*command, "<", *inputs),
            content=stdout,
            stderr=stderr.strip(),
        )
        return raw, finished

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


def _label(vhost: str | None, inputs: list[str]) -> str:
    what = ", ".join(inputs[:3]) + (f" and {len(inputs) - 3} more" if len(inputs) > 3 else "")
    return f"{what} as {vhost}" if vhost else what


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


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
