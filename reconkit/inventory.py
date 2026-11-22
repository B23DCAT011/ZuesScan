"""The attack-surface inventory and the life of a finding (D1).

A run is a snapshot. The inventory is the state of things *across* runs: every host,
service and finding ever seen, with when it was first and last seen, and — for a
finding — where it stands in its life:

    new ──(seen again)──> open ──(claimed fixed)──> fix_claimed ──(not seen)──> fixed
                           │                           └──(seen again)──> fake_fix  ⚠
                           ├──(not seen, nobody claimed a fix)──> gone   (fixed? or down?)
                           └──(risk accepted, with a reason and a date)──> accepted
    fixed / gone ──(seen again)──> reappeared  ⚠

The rule that makes it trustworthy: **"not seen" is only evidence when the run looked**.
A finding is only judged absent if, in that run, its host answered, its port was
scanned (the service is still open, or the profile covers the port the same way as
when the finding was seen) and — for a CVE — the same kind of CVE data was used. A run
that did not look changes nothing.

Pure functions only; the storage layer applies them in the run's transaction.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    NEW = "new"  # seen in one run so far
    OPEN = "open"  # seen again
    FIX_CLAIMED = "fix_claimed"  # someone says it is fixed; the next run will tell
    FIXED = "fixed"  # claimed fixed, and a run that looked no longer sees it
    FAKE_FIX = "fake_fix"  # claimed fixed, but a later run still sees it
    GONE = "gone"  # no longer seen, nobody claimed a fix: fixed? host changed?
    REAPPEARED = "reappeared"  # was fixed or gone, and is back
    ACCEPTED = "accepted"  # risk accepted, with a reason, until a review date


# Statuses that mean "still there, needs attention".
ACTIVE = frozenset(
    {Status.NEW, Status.OPEN, Status.FIX_CLAIMED, Status.FAKE_FIX, Status.REAPPEARED}
)
# Changes worth an alert of their own.
ALERTS = frozenset({Status.FAKE_FIX, Status.REAPPEARED})


@dataclass(frozen=True, slots=True)
class Transition:
    status: Status
    event: str  # what happened, e.g. "fake_fix" — kept in the finding's history


def when_seen(
    status: Status | None, accepted_until: str | None, now: datetime
) -> Transition | None:
    """A run sees the finding. None: nothing worth recording changed."""
    if status is None:
        return Transition(Status.NEW, "new")
    if status == Status.NEW:
        return Transition(Status.OPEN, "seen_again")
    if status == Status.FIX_CLAIMED:
        return Transition(Status.FAKE_FIX, "fake_fix")
    if status in (Status.FIXED, Status.GONE):
        return Transition(Status.REAPPEARED, "reappeared")
    if status == Status.ACCEPTED and accepted_until and accepted_until <= now.date().isoformat():
        return Transition(Status.OPEN, "acceptance_expired")
    return None  # open / fake_fix / reappeared / accepted: still as it was


def when_absent(status: Status) -> Transition | None:
    """A run that looked does not see the finding."""
    if status == Status.FIX_CLAIMED:
        return Transition(Status.FIXED, "verified_fixed")
    if status in (Status.NEW, Status.OPEN, Status.FAKE_FIX, Status.REAPPEARED, Status.ACCEPTED):
        return Transition(Status.GONE, "gone")
    return None  # fixed / gone already


# --- did the run look? ------------------------------------------------------------------------


def cve_data_kind(source: str | None) -> str | None:
    """Runs only compare CVE results made with the same kind of data."""
    if source is None:
        return None
    return "nvd" if source.startswith("NVD cache") else source


def port_scanned(settings: dict[str, Any] | None, port: int) -> bool:
    """Does a profile scan `port` for sure? (A top-N list cannot be known here.)"""
    if not settings:
        return False
    ports = settings.get("ports")
    if ports == "-":
        return True
    if not ports:
        return False
    for item in str(ports).split(","):
        low, _, high = item.partition("-")
        if low.isdigit() and int(low) <= port <= int(high or low):
            return True
    return False


def looked_at(
    *,
    host_answered: bool,
    service_open: bool,
    port: int | None,
    run_profile: dict[str, Any] | None,
    seen_profile: dict[str, Any] | None,
    is_cve: bool,
    run_cve_kind: str | None,
    seen_cve_kind: str | None,
) -> tuple[bool, str]:
    """Did a run look where the finding was? Returns (looked, why not)."""
    if not host_answered:
        return False, "host did not answer"
    if is_cve and (run_cve_kind is None or run_cve_kind != seen_cve_kind):
        return False, "different CVE data"
    if port is None or service_open:
        return True, ""  # the service is there; the issue is not
    if run_profile is not None and run_profile == seen_profile:
        return True, ""  # same ports scanned as when it was seen: the port closed
    if port_scanned(run_profile, port):
        return True, ""
    return False, "port not scanned by this profile"


def host_key(ip: str | None, host: str) -> str:
    """One spelling per machine, as in finding fingerprints."""
    if ip:
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip.strip().lower()
    return host.strip().lower().rstrip(".")


def in_plan(addresses: tuple[str, ...], exclude: tuple[str, ...], ip: str | None) -> bool:
    """Was `ip` among the addresses a run was authorised (and meant) to scan?"""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    def inside(networks: tuple[str, ...]) -> bool:
        for net in networks:
            try:
                if address in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    return inside(addresses) and not inside(exclude)
