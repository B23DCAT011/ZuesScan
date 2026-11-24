"""Alerts waiting to be delivered: what the database's outbox holds (schema 16, G23).

An alert is queued in the database — for a scan, in the same transaction that saves the
run — and delivered afterwards, retried until it is (`zues_scan.server.notify`). A crash
between saving a run and posting its alert therefore loses nothing: the alert is there
when the process comes back, or for the next process that delivers.

`dedupe_key` keeps one condition from alerting again and again: an alert whose key was
queued less than `dedupe_seconds` ago is not queued (e.g. a scheduled scan refused every
hour because its authorisation expired alerts once a day, not every hour).

Standard library only: the core stores alerts; only the service builds and sends them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from zues_scan.inventory_store import FindingEvent
from zues_scan.orchestrator import ScanRun


@dataclass(frozen=True, slots=True)
class Alert:
    kind: str  # run, scan_failed, scan_recovered, refused, job_failed, locked_out, test
    payload: dict[str, Any]  # posted as it is (JSON): Slack's "text" and structured fields
    dedupe_key: str | None = None
    dedupe_seconds: int = 0


@dataclass(frozen=True, slots=True)
class RunFacts:
    """What a policy may look at to decide the alerts of a run being saved."""

    run: ScanRun
    run_id: int
    changes: list[FindingEvent]  # what the run changed in the inventory
    failed_before: int  # failed runs of the same target and profile just before this one


# Decides, inside the transaction that saves a run, which alerts it raises.
AlertPolicy = Callable[[RunFacts], list[Alert]]
