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

* `-ni`: no interactsh, unless a server of your own is configured
  (`ZUES_INTERACTSH_SERVER`, see `zues_scan.plugins.interactsh`). nuclei's default
  servers are ProjectDiscovery's public ones: out-of-band checks would make targets call
  out of the engagement. With your own server, out-of-band templates (Log4Shell, blind
  SSRF) run too; the server is probed before the scan, and if it does not answer, the
  scan goes on with `-ni` and says so.
* `-etags dos,fuzz,intrusive,bruteforce`: no template that floods, fuzzes or tries
  passwords; `-rl`: requests per second capped (the profile's check_rate, else its
  max_rate, else 50).
  Code, headless, file and DAST templates are never enabled (`-code`, `-headless`,
  `-lfa`, `-dast` are not passed).
* `-dut`: only templates whose signature checks out (ProjectDiscovery signs its
  templates): an edited or planted template does not run.
* `-es info`: no informational templates (technology detection, missing headers):
  ZuesScan records weaknesses, not inventory trivia.
* `-duc`: no update check from inside a scan.

Tried, not matched (`verify`): after the CVE stage, a CVE inferred from a version only
(nmap said "Apache 2.4.49") is tried with nuclei's own template for that CVE, on that
service, with `-ms` so that nuclei also reports a template that ran without matching. A
match confirms the finding; a run without a match is written on the finding
(`Finding.tried`) - a fact to triage with (a backported fix, a configuration that is not
vulnerable), never proof. The main pass cannot tell: it runs thousands of templates and
prints only matches. Templates that need interactsh (out-of-band) are left out and never
claimed when there is no server: under `-ni` they cannot match, yet nuclei reports them as
"not matched". With a server they run, and a miss is worded as what it is: no callback
reached the server (the target may not be able to reach it). A template run that ended
in an error (a refused connection, "interactsh client not initialized") is not a try.

Templates: given a directory (`templates`, e.g. the copy pinned in the Docker image),
nuclei runs exactly those, offline, from a fresh configuration directory of its own for
each run — nothing carries over between scans, and the templates' version (from a
`.zues-version` file next to them) is recorded with the run. Without one, nuclei
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

from zues_scan import redact, tools
from zues_scan.plugins import interactsh as oast
from zues_scan.plugins.base import Attempt, ScanError, ScanResult
from zues_scan.profiles import BUILTIN, DEFAULT_PROFILE, ScanProfile
from zues_scan.schema import Asset, Confidence, Finding, RawOutput, ScanTarget, Service, Severity
from zues_scan.scope import Activity

EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")
EXCLUDED_SEVERITIES = ("info",)
NETWORK_PROTOCOLS = ("javascript", "tcp", "ssl")  # nuclei's -pt names for non-web checks
DEFAULT_RATE = 50
# Seconds per request, and retries. A network check (an SSH or TLS handshake) is heavier and
# slower than an HTTP request, and a busy server answers it late: with 10 s and one retry,
# nuclei missed Terrapin on 4 of 10 runs against a CPU-starved sshd (the lab's CI job failed
# twice that way); with 30 s and three retries, 5 of 5. A missed flaw costs more than a
# slower check, and the whole check keeps its time budget either way.
HTTP_TIMEOUT, HTTP_RETRIES = 10, 1
NETWORK_TIMEOUT, NETWORK_RETRIES = 30, 3
# Where the Docker image (or an administrator) says the pinned templates are.
TEMPLATES_ENV = "ZUES_NUCLEI_TEMPLATES"
VERSION_FILE = ".zues-version"
LEGACY_VERSION_FILES = (".reconkit-version",)  # templates installed before the rename

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_TLS_PORTS = {443, 8443, 9443, 4443}


def default_templates() -> str | None:
    """The pinned templates to use: named by the environment (the Docker image), else the
    copy `zues tools install` put in place, if any."""
    return os.environ.get(TEMPLATES_ENV) or tools.managed_templates()


def templates_version(directory: str) -> str | None:
    """The version recorded next to a templates directory (e.g. "10.5.2")."""
    try:
        text = next(
            Path(directory, name).read_text(encoding="utf-8").strip()
            for name in (VERSION_FILE, *LEGACY_VERSION_FILES)
            if Path(directory, name).is_file()
        )
    except (OSError, StopIteration):
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
    activity = Activity.ACTIVE  # sends exploitation checks

    def __init__(
        self,
        profile: ScanProfile | None = None,
        timeout: int | None = None,
        templates: str | None = None,
        interactsh: oast.Interactsh | None = None,
    ) -> None:
        self.profile = profile or BUILTIN[DEFAULT_PROFILE]
        self.timeout = timeout or self.profile.timeout  # for all of this check's runs
        self.rate = self.profile.check_rate or self.profile.max_rate or DEFAULT_RATE
        self.templates = templates
        self.interactsh = interactsh  # a self-hosted server: out-of-band templates run
        self._oast: bool | None = None  # the server answered (asked once per plugin)
        self.clock: Callable[[], float] = time.monotonic  # replaceable in tests

    def is_available(self) -> bool:
        return tools.which("nuclei") is not None

    def version(self) -> str | None:
        """The engine's version, and the templates' when they are pinned:
        "3.11.1 (templates 10.5.2)". Two runs are comparable only with both."""
        try:
            with tempfile.TemporaryDirectory(prefix="zues-nuclei-") as home:
                proc = subprocess.run(
                    [tools.resolve("nuclei"), "-version"],
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

    def oast_ready(self, notes: list[str]) -> bool:
        """Can this check's runs use the configured interactsh server? Asked once; a
        server that does not answer is said in `notes`, and the runs use `-ni`."""
        if self.interactsh is None:
            return False
        if self._oast is None:
            problem = self.interactsh.probe()
            self._oast = problem is None
            if problem:
                notes.append(
                    f"interactsh: {problem}; out-of-band templates (Log4Shell, blind SSRF...) "
                    f"not run"
                )
            else:
                notes.append(f"out-of-band templates on, callbacks to {self.interactsh.domain}")
        return self._oast

    def command(self, vhost: str | None, network: bool = False, oob: bool = False) -> list[str]:
        """The nuclei command; `oob`: with the configured interactsh server (whose token
        `_run` writes to a configuration file, never here)."""
        if oob and self.interactsh is not None:
            callbacks = [
                "-iserver",
                self.interactsh.server,
                "-interactions-cooldown-period",
                str(oast.COOLDOWN),
            ]
        else:
            callbacks = ["-ni"]
        command = [
            tools.resolve("nuclei"),
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            *callbacks,
            "-dut",
            "-etags",
            ",".join(EXCLUDED_TAGS),
            "-es",
            ",".join(EXCLUDED_SEVERITIES),
            "-rl",
            str(self.rate),
            "-timeout",
            str(NETWORK_TIMEOUT if network else HTTP_TIMEOUT),
            "-retries",
            str(NETWORK_RETRIES if network else HTTP_RETRIES),
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
        oob = self.oast_ready(result.notes)
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
            raw, finished = self._run(self.command(vhost, network, oob), inputs, left, oob)
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

    def verify(
        self, plan: ScanTarget, assets: list[Asset], wanted: dict[tuple[str, int], set[str]]
    ) -> ScanResult:
        """Try nuclei's template for each CVE of `wanted` ({(address, port): CVE ids},
        inferred from versions) on those services. Matches come back as findings; a
        template that ran and did not match, in `tried` ({(address, port, CVE): words})."""
        result = ScanResult()
        if not self.is_available():
            return result
        cves = sorted({c.upper() for ids in wanted.values() for c in ids})
        oob = self.oast_ready(result.notes) if cves else False
        index = template_index(self.templates) if self.templates is not None else None
        if index is not None:
            missing = [c for c in cves if c not in index]
            cves = [c for c in cves if c in index]
            if not oob:
                left_out = [c for c in cves if needs_interactsh(index[c])]
                cves = [c for c in cves if c not in left_out]
                if left_out:
                    result.notes.append(
                        f"not tried, their templates need out-of-band callbacks (interactsh, "
                        f"see {oast.SERVER_ENV}): {_list(left_out)}"
                    )
            if missing:
                result.notes.append(f"no template to try: {_list(missing)}")
        if not cves:
            return result
        chosen = [
            Asset(
                host=a.host,
                ip=a.ip,
                names=list(a.names),
                services=[s for s in a.services if (a.ip or "", s.port) in wanted],
            )
            for a in assets
            if a.ip
        ]
        groups = self.targets([a for a in chosen if a.services])
        deadline = self.clock() + min(self.timeout, VERIFY_TIMEOUT)
        failed: dict[tuple[str, int, str], list[str]] = defaultdict(list)
        matched: set[tuple[str, int, str]] = set()
        waited: set[tuple[str, int, str]] = set()  # out-of-band: no callback came
        errors: dict[str, int] = defaultdict(int)
        found: dict[str, Asset] = {}
        for vhost, inputs in groups.items():
            for network, part in (
                (False, [i for i in inputs if "://" in i]),
                (True, [i for i in inputs if "://" not in i]),
            ):
                left = int(deadline - self.clock())
                if not part or left < 1:
                    if part:
                        result.incomplete = True
                        result.notes.append(f"not tried, out of time: {_label(vhost, part)}")
                    continue
                command = [*self.command(vhost, network, oob), "-id", ",".join(cves), "-ms"]
                raw, finished = self._run(command, part, left, oob)
                result.raw.append(raw)
                if not finished:
                    result.incomplete = True
                for line in raw.content.splitlines():
                    outcome = _attempt(line, vhost if not network else None, oob)
                    if outcome is None:
                        continue
                    if isinstance(outcome, str):
                        errors[outcome] += 1
                        continue
                    key, hit, finding, callback = outcome
                    if callback and not hit:
                        waited.add(key)
                    if hit and finding is not None:
                        matched.add(key)
                        found.setdefault(key[0], Asset(host=key[0], ip=key[0])).findings.append(
                            finding
                        )
                    elif not hit:
                        failed[key].append(_where(line, vhost if not network else None))
        services = {(a.ip, s.port, s.protocol): s for a in assets for s in a.services}
        for asset in found.values():
            for f in asset.findings:
                if f.service is not None:
                    f.service = services.get((asset.ip, f.service.port, "tcp"), f.service)
        result.assets = list(found.values())
        version = self.version() or "nuclei"
        for key, places in failed.items():
            ip, port, cve = key
            if key in matched or cve not in wanted.get((ip, port), set()):
                continue
            shown = ", ".join(sorted(set(places))[:3])
            what = f"nuclei {version}: template {cve} ran at {shown} and did not match"
            if key in waited and self.interactsh is not None:
                what = (
                    f"nuclei {version}: template {cve} ran at {shown}; no out-of-band callback "
                    f"reached {self.interactsh.domain} within {oast.COOLDOWN}s (or the target "
                    f"cannot reach that server)"
                )
            result.tried.append(Attempt(ip, port, cve, what))
        if errors:
            result.notes.append(
                "template runs that ended in an error, not counted as tried: "
                + "; ".join(f"{n} x {reason}" for reason, n in sorted(errors.items())[:3])
            )
        result.notes.append(
            f"tried {len(cves)} version-based CVE(s) with their templates: "
            f"{len(matched)} confirmed, {len(result.tried)} not matched"
        )
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

    def _run(
        self, command: list[str], inputs: list[str], timeout: int, oob: bool = False
    ) -> tuple[RawOutput, bool]:
        """One nuclei run; its output and whether it finished in time. `oob`: the
        interactsh server's token goes in a configuration file of the run's own."""
        with tempfile.TemporaryDirectory(prefix="zues-nuclei-") as home:
            env = None
            if oob and self.interactsh is not None:
                settings = Path(home, "interactsh.yaml")
                settings.write_text(self.interactsh.config(), encoding="utf-8")
                command = [*command, "-config", str(settings)]
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
        # The input list is part of what was run: keep it with the command. The exchanges
        # are kept masked (credentials, session cookies, secrets) and responses cut: what
        # proves the finding stays, the target's secrets do not (redact, G24).
        raw = RawOutput(
            plugin=self.name,
            format="nuclei-jsonl",
            command=(*command, "<", *inputs),
            content=redact.nuclei_jsonl(stdout),
            stderr=redact.text(stderr.strip()),
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


VERIFY_TIMEOUT = 300  # seconds for trying the version-based CVEs, at most
_CVE_FILE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_INDEXES: dict[str, dict[str, Path]] = {}


def template_index(templates: str) -> dict[str, Path]:
    """{CVE id: template file} of a templates directory (its CVE-*.yaml files); read
    once per directory and process."""
    if templates not in _INDEXES:
        index: dict[str, Path] = {}
        for path in sorted(Path(templates).rglob("CVE-*.yaml")):
            if _CVE_FILE.fullmatch(path.stem):
                index.setdefault(path.stem.upper(), path)
        _INDEXES[templates] = index
    return _INDEXES[templates]


def needs_interactsh(template: Path) -> bool:
    """Does the template wait for an out-of-band callback ({{interactsh-url}}, an
    interactsh_* matcher)? Unreadable: assume it does (no claim is better than a false one)."""
    try:
        return "interactsh" in template.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return True


def _attempt(
    line: str, vhost: str | None, oob: bool = False
) -> tuple[tuple[str, int, str], bool, Finding | None, bool] | str | None:
    """((address, port, CVE), matched, the finding if matched, out-of-band) of one `-ms`
    line; the error, if the template's run ended in one; None if it says nothing."""
    try:
        hit = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(hit, dict) or "template-id" not in hit:
        return None
    template = str(hit["template-id"]).upper()
    if not _CVE_FILE.fullmatch(template):
        return None
    if hit.get("error") and hit.get("matcher-status") is False:
        # Not a try: nothing (or not all of it) reached the target, or nuclei could not
        # have seen the answer ("interactsh client not initialized").
        return str(hit["error"])[:120]
    url = str(hit.get("matched-at") or hit.get("url") or hit.get("host") or "")
    parts = urlsplit(url if "://" in url else f"tcp://{url}")
    ip = str(hit.get("ip") or parts.hostname or "")
    port = _int(hit.get("port")) or parts.port
    if not ip or port is None:
        return None
    matched = hit.get("matcher-status", True) is not False
    if not matched:
        path = Path(str(hit.get("template-path") or ""))
        if not path.is_file():
            return None
        callback = needs_interactsh(path)
        if callback and not oob:
            return None  # under -ni it could never match: not a try
        return (ip, port, template), False, None, callback
    parsed = _finding(hit, vhost)
    return (ip, port, template), True, parsed[1] if parsed else None, bool(hit.get("interaction"))


def _where(line: str, vhost: str | None) -> str:
    hit = json.loads(line)
    place = str(hit.get("url") or hit.get("host") or "?")
    return f"{place} as {vhost}" if vhost else place


def _list(cves: list[str], shown: int = 5) -> str:
    return ", ".join(cves[:shown]) + (f" and {len(cves) - shown} more" if len(cves) > shown else "")


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
    interaction = hit.get("interaction")
    if isinstance(interaction, dict) and interaction.get("protocol"):
        evidence += f"; out-of-band {interaction['protocol']} callback"
        if interaction.get("remote-address"):
            evidence += f" from {interaction['remote-address']}"
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
