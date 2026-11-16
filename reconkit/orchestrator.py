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

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from reconkit import __version__
from reconkit.cve import CveSource
from reconkit.plugins.base import ScanError, ScannerPlugin
from reconkit.schema import Asset, Finding, ScanTarget
from reconkit.scope import Resolver, Scope


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
    # Plugins that were configured but could not run; the result is partial.
    skipped_plugins: list[str] = field(default_factory=list)
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
    ) -> None:
        self.plugins = plugins
        self.scope = scope
        self.cve_source = cve_source
        self.resolver = resolver  # None = the system resolver

    def run(self, target: str) -> ScanRun:
        # 1. Safety gate: refuse anything outside the authorised scope, and pin down
        #    the exact addresses to scan (names are resolved here, once).
        plan = self.scope.plan(target, self.resolver)

        # 2. Fail loudly if nothing can scan: saving an empty run would look "clean".
        runnable, skipped = self._split_plugins()
        if not runnable:
            raise NoPluginAvailableError(skipped)

        started = now()
        tool_versions = {p.name: p.version() for p in runnable}

        # 3. Run every available plugin; each reports one asset per host it found.
        #    What several plugins say about the same host is merged into one asset.
        assets: list[Asset] = []
        out_of_scope: list[str] = []
        for plugin in runnable:
            for found in plugin.scan(plan):
                # Defence in depth: never trust a tool to stay inside its target.
                # A host it reports outside the scope is dropped, and reported.
                if not self.scope.is_allowed(found.ip or found.host):
                    out_of_scope.append(found.ip or found.host)
                    continue
                known = next((a for a in assets if _same_host(a, found)), None)
                if known is None:
                    assets.append(found)
                else:
                    _merge_into(known, found)

        # 4. CVE stage: match each service against known vulnerabilities.
        if self.cve_source is not None:
            for asset in assets:
                for service in asset.services:
                    asset.findings.extend(self.cve_source.find(service, asset.host))

        # 5. Identify every finding the same way, whichever plugin or stage produced
        #    it: tie it to the merged asset, then fingerprint it. Done here, once,
        #    because only now is it settled which machine each finding belongs to.
        #    Two tools reporting the same issue on the same port is one finding.
        for asset in assets:
            unique: dict[str, Finding] = {}
            for finding in asset.findings:
                finding.asset = asset.host
                finding.ip = asset.ip
                unique.setdefault(finding.compute_fingerprint(), finding)
            asset.findings = list(unique.values())

        return ScanRun(
            target=target,
            started_at=started,
            finished_at=now(),
            assets=assets,
            status=RunStatus.PARTIAL if skipped else RunStatus.COMPLETED,
            tool_versions=tool_versions,
            skipped_plugins=skipped,
            plan=plan,
            out_of_scope=out_of_scope,
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
        if isinstance(error, ScanError):
            failed_plugin = error.plugin
            if error.stderr:
                message = f"{message}\n{error.stderr}"
        return ScanRun(
            target=target,
            started_at=started_at,
            finished_at=now(),
            status=RunStatus.FAILED,
            error=message,
            tool_versions={p.name: p.version() for p in runnable},
            failed_plugin=failed_plugin,
            skipped_plugins=skipped,
        )

    def _split_plugins(self) -> tuple[list[ScannerPlugin], list[str]]:
        """The plugins that can run here, and the names of those that cannot."""
        runnable = [p for p in self.plugins if p.is_available()]
        skipped = [p.name for p in self.plugins if p not in runnable]
        return runnable, skipped


def now() -> str:
    """The current time, as stored in a run: ISO 8601, UTC."""
    return datetime.now(UTC).isoformat()


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
    seen = {(s.port, s.protocol) for s in known.services}
    for service in found.services:
        if (service.port, service.protocol) not in seen:
            seen.add((service.port, service.protocol))
            known.services.append(service)
    known.findings.extend(found.findings)
