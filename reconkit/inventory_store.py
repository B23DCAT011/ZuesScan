"""SQL side of the inventory (D1): applies each saved run to the inventory tables.

The rules (what a run means for a finding's status, when a run "looked") live in
:mod:`reconkit.inventory`; this module only reads and writes rows, inside the
transaction that saves the run, so the inventory can never disagree with the runs.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from reconkit.inventory import (
    ACTIVE,
    Status,
    Transition,
    cve_data_kind,
    host_key,
    in_plan,
    looked_at,
    port_scanned,
    when_absent,
    when_seen,
)
from reconkit.orchestrator import RunStatus, ScanRun
from reconkit.schema import Asset, Finding, Severity


class InventoryError(Exception):
    """A requested change to a finding is not allowed."""


@dataclass(frozen=True, slots=True)
class FindingRow:
    id: int
    fingerprint: str
    host: str
    ip: str | None
    port: int | None
    protocol: str | None
    cve: str | None
    rule_id: str | None
    title: str
    severity: str
    confidence: str | None
    cvss_score: float | None
    kev_added: str | None
    epss: float | None
    status: Status
    status_since: str
    first_seen: str
    last_seen: str
    accepted_until: str | None
    note: str | None

    def as_finding(self) -> Finding:
        """This inventoried finding as a Finding, to rank it like any other."""
        return Finding(
            asset=self.host,
            title=self.title,
            severity=Severity(self.severity),
            cve=self.cve,
            cvss_score=self.cvss_score,
            kev_added=self.kev_added,
            epss=self.epss,
        )


@dataclass(frozen=True, slots=True)
class FindingEvent:
    finding_id: int
    run_id: int | None
    at: str
    event: str
    old_status: str | None
    new_status: str
    actor: str | None
    note: str | None
    title: str = ""
    host: str = ""
    fingerprint: str = ""


def apply_run(conn: sqlite3.Connection, run_id: int, run: ScanRun) -> None:
    """Bring the inventory up to date with what `run` saw (and did not see)."""
    if run.status == RunStatus.FAILED:
        return  # no results: nothing was seen, and nothing can be said to be absent
    at = run.finished_at
    now = datetime.fromisoformat(at)
    answered: dict[str, tuple[int, Asset]] = {}
    for asset in run.assets:
        key = host_key(asset.ip, asset.host)
        answered[key] = (_upsert_host(conn, key, asset, run_id, at), asset)
    _hosts_not_answering(conn, run, set(answered), at)
    for host_id, asset in answered.values():
        _services(conn, host_id, asset, run, run_id, at)
    seen = _findings_seen(conn, answered, run, run_id, at, now)
    _findings_absent(conn, answered, run, run_id, at, seen)


def _upsert_host(conn: sqlite3.Connection, key: str, asset: Asset, run_id: int, at: str) -> int:
    conn.execute(
        "INSERT INTO inv_host (key, host, ip, first_seen, last_seen, first_run, last_run, "
        "state, state_since) VALUES (?, ?, ?, ?, ?, ?, ?, 'up', ?) "
        "ON CONFLICT(key) DO UPDATE SET host = excluded.host, ip = excluded.ip, "
        "last_seen = excluded.last_seen, last_run = excluded.last_run, "
        "state_since = CASE WHEN state = 'up' THEN state_since ELSE excluded.state_since END, "
        "state = 'up'",
        (key, asset.host, asset.ip, at, at, run_id, run_id, at),
    )
    return int(conn.execute("SELECT id FROM inv_host WHERE key = ?", (key,)).fetchone()[0])


def _hosts_not_answering(
    conn: sqlite3.Connection, run: ScanRun, answered: set[str], at: str
) -> None:
    """Known hosts the run was meant to scan, that did not answer this time."""
    plan = run.plan
    if plan is None:
        return
    for row in conn.execute("SELECT id, key, ip FROM inv_host WHERE state = 'up'").fetchall():
        if row["key"] not in answered and in_plan(plan.addresses, plan.exclude, row["ip"]):
            conn.execute(
                "UPDATE inv_host SET state = 'not_responding', state_since = ? WHERE id = ?",
                (at, row["id"]),
            )


def _services(
    conn: sqlite3.Connection, host_id: int, asset: Asset, run: ScanRun, run_id: int, at: str
) -> None:
    profile = _json(run.profile_settings)
    seen = set()
    for s in asset.services:
        seen.add((s.port, s.protocol))
        conn.execute(
            "INSERT INTO inv_service (host_id, port, protocol, name, product, version, "
            "first_seen, last_seen, last_run, seen_profile, state, state_since) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?) "
            "ON CONFLICT(host_id, port, protocol) DO UPDATE SET name = excluded.name, "
            "product = excluded.product, version = excluded.version, "
            "last_seen = excluded.last_seen, last_run = excluded.last_run, "
            "seen_profile = excluded.seen_profile, "
            "state_since = CASE WHEN state = 'open' THEN state_since "
            "ELSE excluded.state_since END, "
            "state = 'open'",
            (
                host_id,
                s.port,
                s.protocol,
                s.name,
                s.product,
                s.version,
                at,
                at,
                run_id,
                profile,
                at,
            ),
        )
    for row in conn.execute(
        "SELECT id, port, protocol, seen_profile FROM inv_service "
        "WHERE host_id = ? AND state = 'open'",
        (host_id,),
    ).fetchall():
        if (row["port"], row["protocol"]) in seen:
            continue
        same_ports = row["seen_profile"] == profile and profile is not None
        if same_ports or port_scanned(run.profile_settings, row["port"]):
            conn.execute(
                "UPDATE inv_service SET state = 'closed', state_since = ? WHERE id = ?",
                (at, row["id"]),
            )


def _findings_seen(
    conn: sqlite3.Connection,
    answered: dict[str, tuple[int, Asset]],
    run: ScanRun,
    run_id: int,
    at: str,
    now: datetime,
) -> set[str]:
    profile = _json(run.profile_settings)
    cve_kind = cve_data_kind(run.cve_source)
    seen: set[str] = set()
    for host_id, asset in answered.values():
        for f in asset.findings:
            if not f.fingerprint.startswith("v2:"):
                continue  # an older fingerprint recipe cannot be matched across runs
            seen.add(f.fingerprint)
            row = conn.execute(
                "SELECT id, status, accepted_until FROM inv_finding WHERE fingerprint = ?",
                (f.fingerprint,),
            ).fetchone()
            values = _finding_values(f, at, run_id, profile, cve_kind)
            if row is None:
                cur = conn.execute(
                    "INSERT INTO inv_finding (fingerprint, host_id, port, protocol, cve, rule_id,"
                    " title, severity, confidence, cvss_score, kev_added, epss, last_seen,"
                    " last_run, seen_profile, seen_cve_kind, first_seen, first_run, status,"
                    " status_since) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                    " ?, 'new', ?)",
                    (f.fingerprint, host_id, *values, at, run_id, at),
                )
                _event(
                    conn, int(cur.lastrowid or 0), run_id, at, None, Transition(Status.NEW, "new")
                )
                continue
            conn.execute(
                "UPDATE inv_finding SET host_id = ?, port = ?, protocol = ?, cve = ?, rule_id = ?,"
                " title = ?, severity = ?, confidence = ?, cvss_score = ?, kev_added = ?,"
                " epss = ?, last_seen = ?, last_run = ?, seen_profile = ?, seen_cve_kind = ?"
                " WHERE id = ?",
                (host_id, *values, row["id"]),
            )
            change = when_seen(Status(row["status"]), row["accepted_until"], now)
            if change is not None:
                _set_status(conn, row["id"], run_id, at, row["status"], change)
    return seen


def _findings_absent(
    conn: sqlite3.Connection,
    answered: dict[str, tuple[int, Asset]],
    run: ScanRun,
    run_id: int,
    at: str,
    seen: set[str],
) -> None:
    open_services = {
        (host_id, s.port, s.protocol)
        for host_id, asset in answered.values()
        for s in asset.services
    }
    host_ids = {host_id for host_id, _ in answered.values()}
    run_kind = cve_data_kind(run.cve_source)
    for row in conn.execute(
        "SELECT id, fingerprint, host_id, port, protocol, cve, status, seen_profile, seen_cve_kind"
        " FROM inv_finding WHERE status NOT IN ('fixed', 'gone')"
    ).fetchall():
        if row["fingerprint"] in seen:
            continue
        looked, _why = looked_at(
            host_answered=row["host_id"] in host_ids,
            service_open=(row["host_id"], row["port"], row["protocol"]) in open_services,
            port=row["port"],
            run_profile=run.profile_settings,
            seen_profile=None if row["seen_profile"] is None else json.loads(row["seen_profile"]),
            is_cve=row["cve"] is not None,
            run_cve_kind=run_kind,
            seen_cve_kind=row["seen_cve_kind"],
        )
        if not looked:
            continue
        change = when_absent(Status(row["status"]))
        if change is not None:
            _set_status(conn, row["id"], run_id, at, row["status"], change)


def _finding_values(
    f: Finding, at: str, run_id: int, profile: str | None, cve_kind: str | None
) -> tuple[Any, ...]:
    svc = f.service
    return (
        svc.port if svc else None,
        svc.protocol if svc else None,
        f.cve,
        f.rule_id,
        f.title,
        str(f.severity),
        None if f.confidence is None else str(f.confidence),
        f.cvss_score,
        f.kev_added,
        f.epss,
        at,
        run_id,
        profile,
        cve_kind if f.cve else None,
    )


def _set_status(
    conn: sqlite3.Connection,
    finding_id: int,
    run_id: int | None,
    at: str,
    old: str | None,
    change: Transition,
    actor: str | None = None,
    note: str | None = None,
) -> None:
    conn.execute(
        "UPDATE inv_finding SET status = ?, status_since = ? WHERE id = ?",
        (str(change.status), at, finding_id),
    )
    _event(conn, finding_id, run_id, at, old, change, actor, note)


def _event(
    conn: sqlite3.Connection,
    finding_id: int,
    run_id: int | None,
    at: str,
    old: str | None,
    change: Transition,
    actor: str | None = None,
    note: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO finding_event (finding_id, run_id, at, event, old_status, new_status, "
        "actor, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (finding_id, run_id, at, change.event, old, str(change.status), actor, note),
    )


def _json(settings: dict[str, Any] | None) -> str | None:
    return None if settings is None else json.dumps(settings, sort_keys=True)


# --- people's decisions ------------------------------------------------------------------------


def decide(
    conn: sqlite3.Connection,
    finding_id: int,
    action: str,
    *,
    actor: str,
    at: str,
    note: str | None = None,
    until: str | None = None,
) -> tuple[str, Status]:
    """Claim a fix, accept the risk, or reopen; returns (old status, new status)."""
    row = conn.execute("SELECT status FROM inv_finding WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        raise InventoryError(f"no finding #{finding_id} in the inventory")
    old = Status(row["status"])
    if action == "claim_fixed":
        if old not in ACTIVE or old == Status.FIX_CLAIMED:
            raise InventoryError(f"finding #{finding_id} is {old}: there is nothing to claim fixed")
        change = Transition(Status.FIX_CLAIMED, "fix_claimed")
    elif action == "accept":
        if not note or not note.strip():
            raise InventoryError("accepting a risk needs a reason (--reason)")
        if not until:
            raise InventoryError("accepting a risk needs a review date (--until YYYY-MM-DD)")
        try:
            review = date.fromisoformat(until)
        except ValueError:
            raise InventoryError(f"--until {until!r} is not a date (YYYY-MM-DD)") from None
        if review.isoformat() <= at[:10]:
            raise InventoryError("the review date must be in the future")
        change = Transition(Status.ACCEPTED, "risk_accepted")
        conn.execute("UPDATE inv_finding SET accepted_until = ? WHERE id = ?", (until, finding_id))
    elif action == "reopen":
        change = Transition(Status.OPEN, "reopened")
        conn.execute("UPDATE inv_finding SET accepted_until = NULL WHERE id = ?", (finding_id,))
    else:
        raise InventoryError(f"unknown action {action!r}")
    if note:
        conn.execute("UPDATE inv_finding SET note = ? WHERE id = ?", (note, finding_id))
    _set_status(conn, finding_id, None, at, str(old), change, actor=actor, note=note)
    return str(old), change.status


# --- reading -----------------------------------------------------------------------------------

_FINDING_SELECT = (
    "SELECT f.*, h.host AS host, h.ip AS ip FROM inv_finding f JOIN inv_host h ON h.id = f.host_id"
)


def findings(conn: sqlite3.Connection, statuses: set[str] | None = None) -> list[FindingRow]:
    rows = conn.execute(f"{_FINDING_SELECT} ORDER BY f.id").fetchall()
    result = [_row(r) for r in rows]
    if statuses is not None:
        result = [r for r in result if r.status in statuses]
    return result


def finding(conn: sqlite3.Connection, finding_id: int) -> FindingRow | None:
    row = conn.execute(f"{_FINDING_SELECT} WHERE f.id = ?", (finding_id,)).fetchone()
    return None if row is None else _row(row)


def status_by_fingerprint(conn: sqlite3.Connection) -> dict[str, str]:
    return {r[0]: r[1] for r in conn.execute("SELECT fingerprint, status FROM inv_finding")}


def events(
    conn: sqlite3.Connection, *, finding_id: int | None = None, run_id: int | None = None
) -> list[FindingEvent]:
    where, args = (
        ("e.finding_id = ?", finding_id) if finding_id is not None else ("e.run_id = ?", run_id)
    )
    rows = conn.execute(
        "SELECT e.*, f.title AS title, f.fingerprint AS fingerprint, h.host AS host "
        "FROM finding_event e "
        "JOIN inv_finding f ON f.id = e.finding_id JOIN inv_host h ON h.id = f.host_id "
        f"WHERE {where} ORDER BY e.id",
        (args,),
    ).fetchall()
    return [
        FindingEvent(
            finding_id=r["finding_id"],
            run_id=r["run_id"],
            at=r["at"],
            event=r["event"],
            old_status=r["old_status"],
            new_status=r["new_status"],
            actor=r["actor"],
            note=r["note"],
            title=r["title"],
            host=r["host"],
            fingerprint=r["fingerprint"],
        )
        for r in rows
    ]


def hosts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    result = []
    for h in conn.execute("SELECT * FROM inv_host ORDER BY id").fetchall():
        services = [
            dict(s)
            for s in conn.execute(
                "SELECT port, protocol, name, product, version, state, first_seen, last_seen "
                "FROM inv_service WHERE host_id = ? ORDER BY port",
                (h["id"],),
            )
        ]
        result.append({**dict(h), "services": services})
    return result


def _row(r: sqlite3.Row) -> FindingRow:
    return FindingRow(
        id=r["id"],
        fingerprint=r["fingerprint"],
        host=r["host"],
        ip=r["ip"],
        port=r["port"],
        protocol=r["protocol"],
        cve=r["cve"],
        rule_id=r["rule_id"],
        title=r["title"],
        severity=r["severity"],
        confidence=r["confidence"],
        cvss_score=r["cvss_score"],
        kev_added=r["kev_added"],
        epss=r["epss"],
        status=Status(r["status"]),
        status_since=r["status_since"],
        first_seen=r["first_seen"],
        last_seen=r["last_seen"],
        accepted_until=r["accepted_until"],
        note=r["note"],
    )


def clear(conn: sqlite3.Connection) -> None:
    for table in ("finding_event", "inv_finding", "inv_service", "inv_host"):
        conn.execute(f"DELETE FROM {table}")
