"""Tests for the audit trail and the terms of the authorisation (G21)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver

from reconkit import cli
from reconkit.audit import GENESIS, AuditKind
from reconkit.orchestrator import Orchestrator, ScanRun
from reconkit.schema import ScanTarget, Service
from reconkit.scope import Scope, ScopeError
from reconkit.storage import Storage

ICT = timezone(timedelta(hours=7))
SCOPE_TEXT = (
    "@engagement PT-2026-014 (ACME)\n"
    "@expires 2026-12-31 +07:00\n"
    "@window Mon-Fri 22:00-06:00 +07:00\n"
    "scanme.lab\n10.0.0.0/24\n"
)


def _scope_file(tmp_path: Path, text: str = SCOPE_TEXT) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text(text, encoding="utf-8", newline="\n")  # the same bytes on every OS
    return path


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    """A moment in November 2026, Vietnam time (Mon 23rd ... Sun 29th)."""
    return datetime(2026, 11, day, hour, minute, tzinfo=ICT)


# --- the terms in the scope file ------------------------------------------------------------


def test_directives_are_read(tmp_path: Path) -> None:
    scope = Scope.from_file(_scope_file(tmp_path))
    assert scope.engagement == "PT-2026-014 (ACME)"
    assert scope.expires == datetime(2027, 1, 1, tzinfo=ICT)  # through the whole 31st
    assert scope.sha256 is not None and len(scope.sha256) == 64
    assert scope.text == SCOPE_TEXT
    assert scope.is_allowed("10.0.0.5")


@pytest.mark.parametrize(
    ("moment", "allowed"),
    [
        (_at(23, 22, 30), True),  # Monday night
        (_at(24, 5, 59), True),  # Tuesday early morning: Monday's window continues
        (_at(24, 6, 0), False),  # the window has closed
        (_at(24, 12, 0), False),  # working hours
        (_at(28, 1, 0), True),  # Saturday 01:00: Friday night's window
        (_at(28, 23, 0), False),  # Saturday night: not a weekday window
        (_at(23, 2, 0), False),  # Monday 02:00 would be Sunday night's window
        (datetime(2026, 11, 23, 15, 30, tzinfo=UTC), True),  # 22:30 in Vietnam, in UTC
    ],
)
def test_time_windows(tmp_path: Path, moment: datetime, allowed: bool) -> None:
    scope = Scope.from_file(_scope_file(tmp_path))
    if allowed:
        scope.check_time(moment)
    else:
        with pytest.raises(ScopeError, match="only authorised"):
            scope.check_time(moment)


def test_expired_authorisation_is_refused(tmp_path: Path) -> None:
    scope = Scope.from_file(_scope_file(tmp_path, "@expires 2026-11-30 +07:00\n10.0.0.0/24\n"))
    scope.check_time(_at(30, 23, 59))
    with pytest.raises(ScopeError, match="expired"):
        scope.check_time(datetime(2026, 12, 1, 0, 0, tzinfo=ICT))


def test_day_lists_and_ranges_that_wrap() -> None:
    scope = Scope.from_entries(["@window Fri-Mon 10:00-12:00", "@window Wed 00:00-24:00"])
    scope.check_time(datetime(2026, 11, 29, 11, 0, tzinfo=UTC))  # Sunday
    scope.check_time(datetime(2026, 11, 25, 23, 59, tzinfo=UTC))  # Wednesday, late
    with pytest.raises(ScopeError):
        scope.check_time(datetime(2026, 11, 24, 11, 0, tzinfo=UTC))  # Tuesday


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("@owner bob", "unknown directive"),
        ("@engagement", "needs a reference"),
        ("@expires soon", "not a date"),
        ("@expires 2026-12-31 GMT+7", "invalid UTC offset"),
        ("@window 25:00-26:00", "not a time of day"),
        ("@window Mon-Fry 09:00-17:00", "not a list of days"),
        ("@window 09:00-09:00", "the same"),
        ("@window 9-17", "hours must look like"),
    ],
)
def test_bad_directives_are_refused(line: str, message: str) -> None:
    with pytest.raises(ScopeError, match=message):
        Scope.from_entries([line])


# --- runs record who, what, under which authorisation ---------------------------------------


def _orch(scope: Scope, **kwargs: object) -> Orchestrator:
    return Orchestrator(
        [FakePlugin([lab_asset(Service(port=22))])],
        scope,
        resolver=lab_resolver,
        clock=lambda: _at(23, 23),
        **kwargs,  # type: ignore[arg-type]
    )


def test_run_records_operator_engagement_and_scope(tmp_path: Path) -> None:
    scope = Scope.from_file(_scope_file(tmp_path))
    run = _orch(scope, operator="alice@lab").run("scanme.lab")
    assert (run.operator, run.engagement) == ("alice@lab", "PT-2026-014 (ACME)")
    assert (run.scope_path, run.scope_sha256) == (scope.path, scope.sha256)
    assert _orch(scope, engagement="PT-2026-099").run("scanme.lab").engagement == "PT-2026-099"


def test_scan_outside_the_window_is_refused_before_anything_runs(tmp_path: Path) -> None:
    scope = Scope.from_file(_scope_file(tmp_path))
    plugin = FakePlugin([lab_asset()])
    orch = Orchestrator([plugin], scope, resolver=lab_resolver, clock=lambda: _at(24, 12))
    with pytest.raises(ScopeError, match="only authorised"):
        orch.run("scanme.lab")
    assert plugin.seen == []


# --- the hash chain -------------------------------------------------------------------------


def _stored(tmp_path: Path) -> tuple[Path, int]:
    db = tmp_path / "audit.db"
    scope = Scope.from_file(_scope_file(tmp_path))
    with Storage(db) as store:
        run_id = store.save_run(_orch(scope, operator="alice@lab").run("scanme.lab"))
        store.record_refusal(
            "8.8.8.8",
            "outside the scope",
            operator="alice@lab",
            engagement=scope.engagement,
            scope_sha256=scope.sha256,
            scope_text=scope.text,
        )
    return db, run_id


def test_every_scan_and_refusal_is_chained(tmp_path: Path) -> None:
    db, run_id = _stored(tmp_path)
    with Storage(db) as store:
        events = store.audit_events()
        report = store.verify_audit()
        loaded = store.load_run(run_id)
        snapshot = store.scope_snapshot(events[0][1].scope_sha256[:12])  # type: ignore[index]
    (_, scan, first), (_, refused, second) = events
    assert scan.kind == AuditKind.SCAN and scan.detail["run_id"] == run_id
    assert scan.detail["plan"]["addresses"] == ["10.0.0.5"]
    assert len(scan.detail["raw_sha256"]) == 1
    assert refused.kind == AuditKind.REFUSED and refused.detail == {"reason": "outside the scope"}
    assert report.intact and report.events == 2 and report.head == second != first
    assert snapshot == SCOPE_TEXT  # stored once, found by a prefix of its hash
    assert loaded is not None
    assert loaded.plan == ScanTarget("scanme.lab", ("10.0.0.5",), hostname="scanme.lab")
    assert loaded.operator == "alice@lab"


def test_changed_event_is_detected(tmp_path: Path) -> None:
    db, _ = _stored(tmp_path)
    with Storage(db) as store:
        store._conn.execute(
            "UPDATE audit_event SET detail = ? WHERE id = 2", (json.dumps({"reason": "ok"}),)
        )
        store._conn.commit()
        report = store.verify_audit()
    assert not report.intact
    assert report.problems == ["event #2: its content was changed after it was written"]


def test_removed_event_is_detected(tmp_path: Path) -> None:
    db, _ = _stored(tmp_path)
    with Storage(db) as store:
        store._conn.execute("DELETE FROM audit_event WHERE id = 1")
        store._conn.commit()
        problems = store.verify_audit().problems
    assert problems == [
        "event #2: does not follow the event before it (an event was removed or reordered)"
    ]


def test_replaced_evidence_is_detected(tmp_path: Path) -> None:
    db, run_id = _stored(tmp_path)
    with Storage(db) as store:
        store._conn.execute(
            "UPDATE scan_run_output SET sha256 = ? WHERE run_id = ?", ("0" * 64, run_id)
        )
        store._conn.commit()
        problems = store.verify_audit().problems
    assert problems == [f"event #1: the raw output of run #{run_id} is not what was recorded"]


def test_deletion_is_on_the_record_but_a_silent_one_is_not(tmp_path: Path) -> None:
    db, run_id = _stored(tmp_path)
    with Storage(db) as store:
        assert store.delete_run(run_id, operator="bob@lab")
        assert store.verify_audit().intact
        (_, deleted, _) = store.audit_events()[-1]
        assert (deleted.kind, deleted.operator, deleted.detail["run_id"]) == (
            AuditKind.DELETED,
            "bob@lab",
            run_id,
        )
    other = tmp_path / "other"
    other.mkdir()
    db2, run2 = _stored(other)
    with Storage(db2) as store:
        store._conn.execute("PRAGMA foreign_keys = ON")
        store._conn.execute("DELETE FROM scan_run WHERE id = ?", (run2,))
        store._conn.commit()
        assert store.verify_audit().problems == [
            f"event #1: run #{run2} is gone, with no record of its deletion"
        ]


def test_empty_chain() -> None:
    with Storage(":memory:") as store:
        report = store.verify_audit()
    assert (report.events, report.head, report.intact) == (0, GENESIS, True)


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def _lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reconkit.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([lab_asset()]))


@pytest.mark.usefixtures("_lab")
def test_cli_records_and_shows_the_trail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "out.db")
    scope = str(_scope_file(tmp_path, "@engagement PT-1\nscanme.lab\n10.0.0.0/24\n"))
    argv = ["scan", "--scope", scope, "--db", db, "--operator", "alice"]
    assert cli.main([*argv, "scanme.lab"]) == 0
    out = capsys.readouterr().out
    assert "authorised by: " in out and "engagement 'PT-1'; operator alice" in out
    assert cli.main([*argv, "203.0.113.9"]) == 3  # refused, and recorded

    capsys.readouterr()
    assert cli.main(["audit", "--db", db, "--verify"]) == 0
    out = capsys.readouterr().out
    assert "alice [PT-1]  scanme.lab: run #1 completed" in out
    assert "203.0.113.9: refused: Target '203.0.113.9' is outside" in out
    assert "chain intact" in out

    assert cli.main(["delete", "1", "--db", db]) == 2  # needs --yes
    assert cli.main(["delete", "1", "--db", db, "--yes", "--operator", "bob"]) == 0
    capsys.readouterr()
    assert cli.main(["audit", "--db", db, "--verify"]) == 0
    assert "bob [PT-1]  scanme.lab: deleted run #1" in capsys.readouterr().out


@pytest.mark.usefixtures("_lab")
def test_cli_audit_reports_tampering_and_prints_scopes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    scope = _scope_file(tmp_path, "scanme.lab\n10.0.0.0/24\n")
    cli.main(["scan", "scanme.lab", "--scope", str(scope), "--db", str(db)])
    with Storage(db) as store:
        sha = store.audit_events()[0][1].scope_sha256
        store._conn.execute("UPDATE audit_event SET target = 'elsewhere'")
        store._conn.commit()
    capsys.readouterr()
    assert cli.main(["audit", "--db", str(db), "--verify"]) == 1
    assert "PROBLEM: event #1: its content was changed" in capsys.readouterr().err
    assert cli.main(["audit", "--db", str(db), "--scope", str(sha)[:10]]) == 0
    assert capsys.readouterr().out == "scanme.lab\n10.0.0.0/24\n"


def test_run_without_audit_context_still_saves() -> None:
    run = ScanRun("10.0.0.5", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00")
    with Storage(":memory:") as store:
        run_id = store.save_run(run)
        (_, event, _) = store.audit_events()[0]
    assert (event.operator, event.scope_sha256, event.detail["run_id"]) == (None, None, run_id)
