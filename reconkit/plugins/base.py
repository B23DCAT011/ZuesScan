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


@runtime_checkable
class ScannerPlugin(Protocol):
    """A recon tool adapter."""

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
