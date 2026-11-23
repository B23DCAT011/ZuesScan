"""The plugin contract every scanner adapter implements.

Adding a new tool (subfinder, nuclei, ...) means writing one class that satisfies
this interface — the orchestrator never changes. A plugin takes a single target and
returns a :class:`ScanResult`: one :class:`~reconkit.schema.Asset` per host, plus the
tool's raw output as evidence. The orchestrator merges the assets that several plugins
report for the same host.

Splitting `parse` from `run` keeps the tool-specific parsing unit-testable without
actually invoking the external binary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from reconkit.schema import Asset, RawOutput, ScanTarget


class ScanError(Exception):
    """A scanner plugin could not produce a trustworthy result.

    Plugins translate every tool-specific failure (binary missing, non-zero exit,
    timeout, unreadable output) into this one type at their boundary, so callers
    handle a single exception instead of knowing how each tool is invoked.

    `stderr` keeps what the tool itself printed, for the user to diagnose with.
    `output` is the tool's raw output, when it produced any before failing: the
    evidence of a failed scan is worth keeping too.
    """

    def __init__(
        self,
        message: str,
        *,
        plugin: str,
        stderr: str | None = None,
        output: RawOutput | None = None,
        no_response: bool = False,
    ) -> None:
        super().__init__(message)
        self.plugin = plugin
        self.stderr = stderr
        self.output = output
        # The tool ran fine but no host answered: for one address family of a
        # dual-stack target this is a finding about reachability, not a broken scan.
        self.no_response = no_response


@dataclass
class ScanResult:
    """What one plugin learnt from one scan."""

    # One asset per host; a host that answered with nothing open is still listed.
    assets: list[Asset] = field(default_factory=list)
    # The tool's own output, exactly as printed (usually one per invocation).
    raw: list[RawOutput] = field(default_factory=list)
    # What a person should know about how the scan went, e.g. "IPv6: no host answered".
    notes: list[str] = field(default_factory=list)
    # CVEs shown NOT to affect a host (address -> CVE ids), e.g. because an installed
    # package carries the fix: version-based guesses for them are withdrawn.
    cleared: dict[str, set[str]] = field(default_factory=dict)
    # The tool stopped before it finished (its time limit): what it found so far is
    # kept, and the run is marked partial - absence of a finding proves nothing.
    incomplete: bool = False


@runtime_checkable
class ScannerPlugin(Protocol):
    """A recon tool adapter.

    Every plugin should also say how far it goes with a target, as a class attribute
    `activity` (`reconkit.scope.Activity`: passive, scan or active). The scope's
    `@activity` ceiling is checked against it before anything is sent; a plugin that
    does not say is assumed to go as far as its kind can (see `Orchestrator.activities`).
    """

    name: str

    def is_available(self) -> bool:
        """True if the underlying binary is installed and runnable."""
        ...

    def version(self) -> str | None:
        """The version of the underlying tool, or None if it cannot be determined.

        Recorded with every run: two runs are only comparable if you know which
        version of the tool produced each. Must not raise.
        """
        ...

    def scan(self, target: ScanTarget) -> ScanResult:
        """Scan `target.addresses` (minus `target.exclude`); return one `Asset` per host.

        The addresses were authorised by the scope guard: a plugin must scan exactly
        those and must not resolve or expand the target on its own.

        A target may be a single host or a whole range, so the unit of a result is
        the host, never the target. Each asset carries what this tool learnt about
        that host: its address, its services, its findings.

        The result also carries the tool's raw output, unmodified: ReconKit stores it
        as the evidence for everything it derived from this scan.

        Raises :class:`ScanError` if the tool fails; never returns a partial or
        empty result to signal failure.
        """
        ...


@dataclass
class DiscoveryResult:
    """What a discovery plugin found: names, not yet checked against the scope."""

    names: list[str] = field(default_factory=list)
    raw: list[RawOutput] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@runtime_checkable
class DiscoveryPlugin(Protocol):
    """A tool that finds *names* to scan (subdomains), without touching the targets.

    It never decides what gets scanned: every name it returns goes through the scope
    guard (`Scope.plan_discovered`), which resolves it and checks every address.
    """

    name: str

    def is_available(self) -> bool: ...

    def version(self) -> str | None: ...

    def discover(self, domain: str) -> DiscoveryResult:
        """Names under `domain`. Raises :class:`ScanError` if the tool fails."""
        ...


@runtime_checkable
class CheckPlugin(Protocol):
    """A tool that tests what the port scan found (nuclei on web services).

    It runs after the scanners, on the merged hosts, and may only look at those hosts'
    addresses. Findings come back as assets (one per host, matched by address).
    """

    name: str

    def is_available(self) -> bool: ...

    def version(self) -> str | None: ...

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        """Findings for `assets`. Raises :class:`ScanError` if the tool fails."""
        ...
