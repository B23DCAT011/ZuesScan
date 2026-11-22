"""Audit trail: who scanned what, when, under which authorisation (G21).

Every scan, refusal and deletion appends one :class:`AuditEvent` to the database.
The events form a **hash chain**: each one's `hash` covers its own fields and the
previous event's hash, starting from `GENESIS`. Changing, removing or reordering a
past event breaks every hash after it, which `verify` reports.

What the chain proves, and what it does not: it detects a database edited after the
fact. Someone with write access could rebuild the whole chain, so the latest hash
(the *head*) must also be kept somewhere they cannot write — printed into a ticket,
a log server, an email to the client. Comparing that copy with the current head then
shows whether history was rewritten.

Each scan event also carries the SHA-256 of the scanners' raw output, tying the
evidence into the chain.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64


class AuditKind:
    SCAN = "scan"  # a run was saved (completed, partial or failed)
    REFUSED = "refused"  # the scope guard refused the request: nothing was probed
    DELETED = "deleted"  # a stored run was deleted
    FINDING = "finding"  # a person changed a finding's status (claimed fixed, accepted, ...)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    at: str  # ISO 8601, UTC
    kind: str
    target: str
    operator: str | None
    engagement: str | None
    scope_sha256: str | None
    detail: dict[str, Any] = field(default_factory=dict)

    def fields(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "kind": self.kind,
            "target": self.target,
            "operator": self.operator,
            "engagement": self.engagement,
            "scope_sha256": self.scope_sha256,
            "detail": self.detail,
        }


def chain_hash(prev_hash: str, event: AuditEvent) -> str:
    """The hash of `event` linked after `prev_hash`."""
    canonical = json.dumps(event.fields(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}\n{canonical}".encode()).hexdigest()


def default_operator() -> str:
    """Who is running ReconKit, as the operating system knows it: user@host."""
    try:
        user = getpass.getuser()
    except (OSError, KeyError):
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


@dataclass(frozen=True, slots=True)
class ChainReport:
    events: int
    head: str  # hash of the last event (GENESIS if there is none)
    problems: list[str]

    @property
    def intact(self) -> bool:
        return not self.problems
