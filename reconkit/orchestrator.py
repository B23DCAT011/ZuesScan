"""Orchestrator — drives a scan through the pipeline, tool-agnostic.

It knows the *order of stages*, not the details of any tool:

    scope gate (resolve + plan)  ->  run each available plugin  ->  re-check and
    merge assets per host  ->  CVE stage  ->  fingerprint every finding

One target can be many hosts (a CIDR range), so a run holds one `Asset` per host.

A scan that could not run is an error, never an empty result: a run with zero
services must mean "we looked and found nothing", not "we did not look". Such a scan
is still worth remembering, as a run whose status is `failed` (see `failed_run`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from reconkit import __version__
from reconkit.cve import CveSource
from reconkit.plugins.base import CheckPlugin, DiscoveryPlugin, ScanError, ScannerPlugin
from reconkit.profiles import ScanProfile
from reconkit.schema import Asset, Confidence, Finding, RawOutput, ScanTarget
from reconkit.scope import Activity, Resolver, Scope, ScopeError

log = logging.getLogger(__name__)

DISCOVER_LIMIT = 1000


class NoPluginAvailableError(Exception):
    """None of the configured scanner plugins can run on this machine."""

    def __init__(self, plugins: list[str]) -> None:
        self.plugins = plugins
        if plugins:
            names = ", ".join(plugins)
            message = f"no scanner available: {names} not installed or not on PATH"
        else:
            message = "no scanner configured"
        super().__init__(message)


class RunStatus(StrEnum):
    """How a scan run ended."""

    COMPLETED = "completed"  # every configured scanner ran
    PARTIAL = "partial"  # some scanners could not run: the result has blind spots
    FAILED = "failed"  # nothing trustworthy was produced; see `ScanRun.error`


@dataclass
class ScanRun:
    """The result of one scan of one target: one asset per host found."""

    target: str
    started_at: str
    finished_at: str
    assets: list[Asset] = field(default_factory=list)
    status: RunStatus = RunStatus.COMPLETED
    # Why the run failed (only when `status` is FAILED).
    error: str | None = None
    # Version of each scanner that was started, e.g. {"nmap": "7.92"}: results are
    # only comparable between runs if you know which tool produced them.
    tool_versions: dict[str, str | None] = field(default_factory=dict)
    # The scanner whose failure failed the run, if it was a scanner.
    failed_plugin: str | None = None
    reconkit_version: str | None = __version__
    # What each scanner printed, untouched: the evidence behind everything above.
    raw_outputs: list[RawOutput] = field(default_factory=list)
    # Plugins that were configured but could not run; the result is partial.
    skipped_plugins: list[str] = field(default_factory=list)
    # The scan profile the scanners ran with, and its exact settings: a run is only
    # comparable with another run of the same profile (a quick scan does not look at
    # the ports a full scan does).
    profile: str | None = None
    profile_settings: dict[str, Any] | None = None
    # What a person should know about how the run went (a scanner's notes, choices
    # such as "IPv4 only" that narrowed what was looked at).
    notes: list[str] = field(default_factory=list)
    # Under which authorisation the run happened (G21): who ran it, the engagement
    # it belongs to, and the scope file (path + SHA-256 of its exact content).
    operator: str | None = None
    engagement: str | None = None
    scope_path: str | None = None
    scope_sha256: str | None = None
    scope_text: str | None = None  # the scope file as it was: kept once per version
    # Which CVE data the run matched against (None: no CVE stage). Runs only compare
    # CVE findings made with the same kind of data.
    cve_source: str | None = None
    # What the scope guard authorised for this run: resolved addresses, exclusions.
    plan: ScanTarget | None = None
    # Hosts a plugin reported that are outside the scope; dropped from `assets`.
    out_of_scope: list[str] = field(default_factory=list)


class Orchestrator:
    """Runs the recon pipeline for a single target."""

    def __init__(
        self,
        plugins: list[ScannerPlugin],
        scope: Scope,
        cve_source: CveSource | None = None,
        resolver: Resolver | None = None,
        profile: ScanProfile | None = None,
        ipv4_only: bool = False,
        operator: str | None = None,
        engagement: str | None = None,
        clock: Callable[[], datetime] | None = None,
        discovery: list[DiscoveryPlugin] | None = None,
        checks: list[CheckPlugin] | None = None,
        discover_limit: int = DISCOVER_LIMIT,
    ) -> None:
        self.plugins = plugins
        self.scope = scope
        self.cve_source = cve_source
        self.resolver = resolver  # None = the system resolver
        # Recorded with every run; the plugins were built with it.
        self.profile = profile
        # Do not look up IPv6 (AAAA) addresses of a name: narrower, and noted as such.
        self.ipv4_only = ipv4_only
        self.operator = operator
        # The engagement given for this run, else the one the scope file states.
        self.engagement = engagement or scope.engagement
        self.clock = clock or (lambda: datetime.now(UTC))
        # Name-finding plugins (subfinder): when set, a domain target is first expanded
        # into the names found under it, each checked against the scope.
        self.discovery = discovery or []
        # At most this many discovered names are resolved and considered: sources can
        # return tens of thousands, mostly junk.
        self.discover_limit = discover_limit
        # Plugins that test what the scan found (nuclei), after the scanners.
        self.checks = checks or []

    def run(self, target: str) -> ScanRun:
        # 1. Safety gate: refuse anything outside the authorised scope, and pin down
        #    the exact addresses to scan (names are resolved here, once).
        self.scope.check_time(self.clock())  # expired, or outside the agreed hours?
        self.scope.check_activity(self.activities())  # exploitation checks authorised?
        notes: list[str] = []
        raw_outputs: list[RawOutput] = []
        discovered_versions: dict[str, str | None] = {}
        if self.discovery:
            plan = self._discover(target, notes, raw_outputs, discovered_versions)
        else:
            plan = self.scope.plan(target, self.resolver, ipv4_only=self.ipv4_only)
        log.info(
            "scan of %s authorised: addresses %s, excluded %s",
            target,
            ",".join(plan.addresses),
            ",".join(plan.exclude) or "none",
            extra={"event": "scan.planned", "target": target},
        )

        # 2. Fail loudly if nothing can scan: saving an empty run would look "clean".
        runnable, skipped = self._split_plugins()
        if not runnable:
            raise NoPluginAvailableError(skipped)

        started = now()
        tool_versions = {**discovered_versions, **{p.name: p.version() for p in runnable}}

        # 3. Run every available plugin; each reports one asset per host it found.
        #    What several plugins say about the same host is merged into one asset.
        assets: list[Asset] = []
        out_of_scope: list[str] = []
        if self.ipv4_only and (plan.hostname or plan.names):
            notes.append("IPv4 only: the name's IPv6 (AAAA) addresses were not looked up")
        for plugin in runnable:
            clock = time.monotonic()
            log.info("%s: scanning %s", plugin.name, target, extra={"event": "plugin.start"})
            result = plugin.scan(plan)
            log.info(
                "%s: %d host(s) in %.1f s",
                plugin.name,
                len(result.assets),
                time.monotonic() - clock,
                extra={"event": "plugin.done", "plugin": plugin.name},
            )
            notes.extend(f"{plugin.name}: {note}" for note in result.notes)
            # Kept whole, including what it says about hosts dropped just below:
            # it is the record of what the tool really did.
            raw_outputs.extend(result.raw)
            for found in result.assets:
                # Defence in depth: never trust a tool to stay inside its target.
                # A host it reports outside the scope is dropped, and reported.
                if not self.scope.is_allowed(found.ip or found.host):
                    log.warning(
                        "%s reported %s, outside the scope: dropped",
                        plugin.name,
                        found.ip or found.host,
                        extra={"event": "scope.dropped"},
                    )
                    out_of_scope.append(found.ip or found.host)
                    continue
                known = next((a for a in assets if _same_host(a, found)), None)
                if known is None:
                    assets.append(found)
                else:
                    _merge_into(known, found)

        # Name every host after the names the scope guard resolved to it, whichever
        # scanner reported it: tools see addresses, the names come from the plan.
        for asset in assets:
            names = plan.names_for(asset.ip or "")
            if names:
                asset.host, asset.names = names[0], names
            elif plan.hostname and not asset.names:
                asset.names = [plan.hostname]

        # 3b. Checks (nuclei): test what was found. Before the CVE stage, so that an
        #     observed issue is kept over the same CVE inferred from a version.
        cleared: dict[str, set[str]] = {}
        degraded = False  # a check failed or ran out of time: the run is partial
        for check in self.checks:
            if not check.is_available():
                skipped.append(check.name)
                continue
            tool_versions[check.name] = check.version()
            clock = time.monotonic()
            try:
                result = check.check(plan, assets)
            except ScanError as exc:
                # The port scan already succeeded: a broken check must not throw its
                # results away. The run is kept as partial, with what went wrong.
                degraded = True
                notes.append(f"{check.name} failed, its checks are missing: {exc}")
                if exc.output is not None:
                    raw_outputs.append(exc.output)
                log.warning(
                    "%s failed: %s",
                    check.name,
                    exc,
                    extra={"event": "check.failed", "plugin": check.name},
                )
                continue
            degraded = degraded or result.incomplete
            raw_outputs.extend(result.raw)
            notes.extend(f"{check.name}: {note}" for note in result.notes)
            for ip, cves in result.cleared.items():
                cleared.setdefault(ip, set()).update(cves)
            for found in result.assets:
                known = next((a for a in assets if _same_host(a, found)), None)
                if known is None or not self.scope.is_allowed(found.ip or found.host):
                    continue  # a check may only report on hosts the scan found
                known.findings.extend(found.findings)
            log.info(
                "%s: %d finding(s) in %.1f s",
                check.name,
                sum(len(a.findings) for a in result.assets),
                time.monotonic() - clock,
                extra={"event": "check.done", "plugin": check.name},
            )

        # 4. CVE stage: match each service against known vulnerabilities.
        if self.cve_source is not None:
            for asset in assets:
                for service in asset.services:
                    asset.findings.extend(self.cve_source.find(service, asset.host))
            log.info(
                "CVE stage (%s): %d finding(s)",
                self.cve_source.name,
                sum(len(a.findings) for a in assets),
                extra={"event": "cve.done"},
            )

        # 4b. A check that saw the installed packages outranks a guess from a banner: a
        #     tentative version match for a CVE it showed fixed on that host is withdrawn.
        for asset in assets:
            fixed = cleared.get(asset.ip or "", set())
            if not fixed:
                continue
            kept = [
                f
                for f in asset.findings
                if not (f.cve in fixed and f.confidence in (Confidence.TENTATIVE, Confidence.FIRM))
                or (f.rule_id or "").startswith("debian:")
            ]
            if len(kept) < len(asset.findings):
                notes.append(
                    f"{asset.ip}: {len(asset.findings) - len(kept)} version-based finding(s) "
                    "withdrawn: the installed packages carry the fix"
                )
                asset.findings = kept

        # 5. Identify every finding the same way, whichever plugin or stage produced
        #    it: tie it to the merged asset, then fingerprint it. Done here, once,
        #    because only now is it settled which machine each finding belongs to.
        #    Two tools reporting the same issue on the same port is one finding.
        for asset in assets:
            unique: dict[str, Finding] = {}
            for finding in asset.findings:
                finding.asset = asset.host
                finding.ip = asset.ip
                key = finding.compute_fingerprint()
                if key in unique:
                    _merge_finding(unique[key], finding)
                else:
                    unique[key] = finding
            asset.findings = list(unique.values())

        return ScanRun(
            target=target,
            started_at=started,
            finished_at=now(),
            assets=assets,
            status=RunStatus.PARTIAL if skipped or degraded else RunStatus.COMPLETED,
            tool_versions=tool_versions,
            skipped_plugins=skipped,
            plan=plan,
            out_of_scope=out_of_scope,
            raw_outputs=raw_outputs,
            notes=notes,
            **self._profile_record(),
        )

    def failed_run(self, target: str, started_at: str, error: Exception) -> ScanRun:
        """Describe a scan that `run()` gave up on, so that the failure can be stored.

        A scan that fails every night must leave a trace: with no record at all, "the
        scan is broken" looks exactly like "nobody scanned". The run carries the error
        and no asset, so it can never be read as "scanned, nothing found".
        """
        runnable, skipped = self._split_plugins()
        message = str(error)
        failed_plugin = None
        raw_outputs: list[RawOutput] = []
        if isinstance(error, ScanError):
            failed_plugin = error.plugin
            if error.stderr:
                message = f"{message}\n{error.stderr}"
            if error.output is not None:
                raw_outputs.append(error.output)
        return ScanRun(
            target=target,
            started_at=started_at,
            finished_at=now(),
            status=RunStatus.FAILED,
            error=message,
            tool_versions={p.name: p.version() for p in runnable},
            failed_plugin=failed_plugin,
            skipped_plugins=skipped,
            raw_outputs=raw_outputs,
            **self._profile_record(),
        )

    def _discover(
        self,
        target: str,
        notes: list[str],
        raw_outputs: list[RawOutput],
        versions: dict[str, str | None],
    ) -> ScanTarget:
        """Find the names under `target`, keep those the scope allows, plan them."""
        domain = target.strip().lower().rstrip(".")
        if "." not in domain:
            raise ScopeError(
                f"Looking for names under {domain!r} is not supported: a wildcard over a "
                "top-level name would authorise far too much."
            )
        if not self.scope.allows_discovery(domain):
            raise ScopeError(
                f"Looking for names under {domain!r} needs '*.{domain}' (or a wider "
                "wildcard) in the scope: discovered names are only scanned if authorised."
            )
        usable = [p for p in self.discovery if p.is_available()]
        if not usable:
            raise NoPluginAvailableError([p.name for p in self.discovery])
        found: list[str] = []
        for plugin in usable:
            versions[plugin.name] = plugin.version()
            result = plugin.discover(domain)
            raw_outputs.extend(result.raw)
            notes.extend(f"{plugin.name}: {n}" for n in result.notes)
            found += result.names
            log.info("%s: %d name(s) under %s", plugin.name, len(result.names), domain)
        # The names closest to the domain first (api.example.com before
        # a.b.c.example.com): real hosts are mostly there, junk mostly deep.
        unique = sorted(set(found), key=lambda n: (n.count("."), len(n), n))
        considered = unique[: self.discover_limit]
        if len(unique) > len(considered):
            notes.append(
                f"discovery: {len(unique)} name(s) found, only the {len(considered)} closest "
                f"to {domain} considered (limit {self.discover_limit}); all are in the raw output"
            )
        plan, skipped = self.scope.plan_discovered(
            domain, considered, self.resolver, ipv4_only=self.ipv4_only
        )
        names = sorted({n for n, _ in plan.names})
        notes.append(
            f"discovery: {len(unique)} name(s) found under {domain}; "
            f"{len(names)} in scope and scanned"
        )
        notes += _summarise_skipped(skipped)
        return plan

    def activities(self) -> list[tuple[str, Activity]]:
        """What each requested plugin does to a target, as it declares (`activity`).

        A plugin that does not say is assumed to go as far as its kind can: a scanner
        scans, a discovery plugin scans (it may query the target's DNS), and a check
        is active — an undeclared check must not slip past `@activity`.
        """
        declared: list[tuple[str, Activity]] = []
        for kind, default in (
            (self.plugins, Activity.SCAN),
            (self.discovery, Activity.SCAN),
            (self.checks, Activity.ACTIVE),
        ):
            declared += [(p.name, getattr(p, "activity", default)) for p in kind]
        return declared

    def _profile_record(self) -> dict[str, Any]:
        """What every run records about how and under which authorisation it ran."""
        record: dict[str, Any] = {
            "operator": self.operator,
            "engagement": self.engagement,
            "scope_path": self.scope.path,
            "scope_sha256": self.scope.sha256,
            "scope_text": self.scope.text,
            "cve_source": None if self.cve_source is None else self.cve_source.name,
        }
        if self.profile is not None:
            record["profile"] = self.profile.name
            record["profile_settings"] = self.profile.settings()
        return record

    def _split_plugins(self) -> tuple[list[ScannerPlugin], list[str]]:
        """The plugins that can run here, and the names of those that cannot."""
        runnable = [p for p in self.plugins if p.is_available()]
        skipped = [p.name for p in self.plugins if p not in runnable]
        return runnable, skipped


def now() -> str:
    """The current time, as stored in a run: ISO 8601, UTC."""
    return datetime.now(UTC).isoformat()


def _summarise_skipped(skipped: list[tuple[str, str]], shown: int = 20) -> list[str]:
    """Notes about the names not scanned: the first few with their reason, then a count
    (one note per name would bury the run under thousands of lines)."""
    notes = [f"not scanned: {name}: {why}" for name, why in skipped[:shown]]
    if len(skipped) > shown:
        notes.append(
            f"not scanned: {len(skipped) - shown} more name(s), for the same kinds of reason"
        )
    return notes


def _merge_finding(kept: Finding, other: Finding) -> None:
    """Fold a second report of the same issue into the first one kept.

    The first one wins on identity and confidence (checks run before the CVE stage, so
    an observed issue is kept over the same CVE inferred from a version). Facts about
    the vulnerability itself come from the vulnerability database when one of the two
    is a database match (no `rule_id`): its CVSS, KEV date and EPSS are the curated
    ones, a template's are copies made when it was written. Nothing known is lost.
    """
    curated = other if other.rule_id is None and kept.rule_id is not None else None
    if curated is not None:
        kept.severity = curated.severity
        kept.cvss_score = curated.cvss_score if curated.cvss_score is not None else kept.cvss_score
        kept.cvss_vector = curated.cvss_vector or kept.cvss_vector
        kept.cwe = curated.cwe or kept.cwe
        kept.kev_added = curated.kev_added or kept.kev_added
        kept.epss = curated.epss if curated.epss is not None else kept.epss
    else:
        kept.cvss_score = kept.cvss_score if kept.cvss_score is not None else other.cvss_score
        kept.cvss_vector = kept.cvss_vector or other.cvss_vector
        kept.cwe = kept.cwe or other.cwe
        kept.kev_added = kept.kev_added or other.kev_added
        kept.epss = kept.epss if kept.epss is not None else other.epss
    kept.description = kept.description or other.description
    if other.evidence and other.evidence not in kept.evidence:
        kept.evidence = (
            f"{kept.evidence}\nAlso: {other.evidence}" if kept.evidence else other.evidence
        )


def _same_host(a: Asset, b: Asset) -> bool:
    """Do two plugin reports describe the same machine?

    The IP decides whenever both reports have one: one name can point at several
    machines. A report without an IP (a tool that only lists names) is matched by name.
    """
    if a.ip and b.ip:
        return a.ip == b.ip
    return a.host.lower() == b.host.lower()


def _merge_into(known: Asset, found: Asset) -> None:
    """Add what another plugin learnt about the same host to `known`."""
    if known.ip is None:
        known.ip = found.ip
    if not known.route:
        known.route = list(found.route)  # one path per host: the first one traced wins
    seen = {(s.port, s.protocol) for s in known.services}
    for service in found.services:
        if (service.port, service.protocol) not in seen:
            seen.add((service.port, service.protocol))
            known.services.append(service)
    known.findings.extend(found.findings)
