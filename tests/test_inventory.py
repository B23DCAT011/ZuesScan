"""Tests for the inventory, the finding lifecycle and run diffs (D1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from zues_scan.diff import diff_runs
from zues_scan.inventory import Status, looked_at, port_scanned, when_absent, when_seen
from zues_scan.inventory_store import InventoryError
from zues_scan.orchestrator import RunStatus, ScanRun
from zues_scan.profiles import BUILTIN
from zues_scan.schema import Asset, Finding, ScanTarget, Service, Severity
from zues_scan.storage import Storage

STANDARD = BUILTIN["standard"].settings()
QUICK = BUILTIN["quick"].settings()
FULL = BUILTIN["full"].settings()
PLAN = ScanTarget(requested="10.0.0.0/24", addresses=("10.0.0.0/24",))

SSH_OLD = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
SSH_NEW = Service(port=22, name="ssh", product="OpenSSH", version="9.9")
MYSQL = Service(port=3306, name="mysql", product="MySQL", version="8.0.37")


def _finding(service: Service, cve: str = "CVE-2018-15473") -> Finding:
    f = Finding(asset="10.0.0.5", ip="10.0.0.5", title=f"issue {cve}", service=service, cve=cve)
    f.severity = Severity.MEDIUM
    f.compute_fingerprint()
    return f


_DAY = iter(range(1, 29))


def _run(
    *services: Service,
    findings: list[Finding] | None = None,
    answered: bool = True,
    profile: dict[str, object] | None = None,
    cve_source: str | None = "local-seed",
    status: RunStatus = RunStatus.COMPLETED,
    day: int | None = None,
) -> ScanRun:
    d = day or next(_DAY)
    assets = []
    if answered:
        assets.append(
            Asset(
                host="10.0.0.5",
                ip="10.0.0.5",
                services=list(services),
                findings=list(findings or []),
            )
        )
    return ScanRun(
        "10.0.0.0/24",
        f"2026-11-{d:02d}T01:00:00+00:00",
        f"2026-11-{d:02d}T01:05:00+00:00",
        assets=assets,
        status=status,
        plan=PLAN,
        profile="custom" if profile not in (STANDARD, None) else "standard",
        profile_settings=STANDARD if profile is None else profile,
        cve_source=cve_source,
    )


def _status(store: Storage) -> Status:
    (row,) = store.inventory_findings()
    return row.status


def _events(store: Storage) -> list[str]:
    (row,) = store.inventory_findings()
    return [e.event for e in store.finding_history(row.id)]


@pytest.fixture
def store(tmp_path: Path) -> Storage:
    return Storage(tmp_path / "inv.db")


# --- the rules on their own ---------------------------------------------------------------------


def test_lifecycle_rules() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 11, 22, tzinfo=UTC)
    assert when_seen(None, None, now).status == Status.NEW  # type: ignore[union-attr]
    assert when_seen(Status.FIX_CLAIMED, None, now).status == Status.FAKE_FIX  # type: ignore[union-attr]
    assert when_seen(Status.GONE, None, now).status == Status.REAPPEARED  # type: ignore[union-attr]
    assert when_seen(Status.OPEN, None, now) is None
    assert when_seen(Status.ACCEPTED, "2026-12-01", now) is None
    assert when_seen(Status.ACCEPTED, "2026-11-22", now).status == Status.OPEN  # type: ignore[union-attr]
    assert when_absent(Status.FIX_CLAIMED).status == Status.FIXED  # type: ignore[union-attr]
    assert when_absent(Status.OPEN).status == Status.GONE  # type: ignore[union-attr]
    assert when_absent(Status.FIXED) is None


def test_ports_a_profile_certainly_scans() -> None:
    assert port_scanned(FULL, 3306)
    assert port_scanned({"ports": "22,80,3000-4000"}, 3306)
    assert not port_scanned({"ports": "22,80"}, 3306)
    assert not port_scanned(QUICK, 22)  # top 100: which ones is nmap's business
    assert not port_scanned(None, 22)


def test_not_seen_only_counts_when_the_run_looked() -> None:
    base: dict[str, Any] = {
        "host_answered": True,
        "service_open": False,
        "port": 3306,
        "run_profile": QUICK,
        "seen_profile": STANDARD,
        "is_cve": True,
        "run_cve_kind": "local-seed",
        "seen_cve_kind": "local-seed",
    }
    assert looked_at(**base) == (False, "port not scanned by this profile")
    assert looked_at(**{**base, "service_open": True})[0]
    assert looked_at(**{**base, "run_profile": STANDARD})[0]
    assert looked_at(**{**base, "host_answered": False}) == (False, "host did not answer")
    no_cve = {**base, "service_open": True, "run_cve_kind": None}
    assert looked_at(**no_cve)[1] == "different CVE data"


# --- the whole story, run by run ----------------------------------------------------------------


def test_new_open_claimed_fake_fix_fixed_reappeared(store: Storage) -> None:
    issue = _finding(SSH_OLD)
    store.save_run(_run(SSH_OLD, findings=[issue]))
    assert _status(store) == Status.NEW
    store.save_run(_run(SSH_OLD, findings=[issue]))
    assert _status(store) == Status.OPEN
    (row,) = store.inventory_findings()

    assert store.decide_finding(row.id, "claim_fixed", actor="bob") == Status.FIX_CLAIMED
    run3 = store.save_run(_run(SSH_OLD, findings=[issue]))  # still there!
    assert _status(store) == Status.FAKE_FIX
    assert [e.event for e in store.changes_in_run(run3)] == ["fake_fix"]

    store.decide_finding(row.id, "claim_fixed", actor="bob")
    store.save_run(_run(SSH_NEW))  # host answers, ssh upgraded, the issue is gone
    assert _status(store) == Status.FIXED

    store.save_run(_run(SSH_OLD, findings=[issue]))  # downgraded again
    assert _status(store) == Status.REAPPEARED
    assert _events(store) == [
        "new",
        "seen_again",
        "fix_claimed",
        "fake_fix",
        "fix_claimed",
        "verified_fixed",
        "reappeared",
    ]
    assert store.verify_audit().intact  # decisions are in the hash chain too
    kinds = [e.kind for _, e, _ in store.audit_events()]
    assert kinds.count("finding") == 2


def test_gone_without_a_claim(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(SSH_NEW))
    assert _status(store) == Status.GONE


def test_host_that_did_not_answer_changes_nothing(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(answered=False))  # down, or filtered: no evidence either way
    assert _status(store) == Status.NEW
    (host,) = store.inventory_hosts()
    assert host["state"] == "not_responding"
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    assert store.inventory_hosts()[0]["state"] == "up"


def test_run_with_other_cve_data_changes_nothing(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(SSH_OLD, cve_source=None))  # --no-cve
    assert _status(store) == Status.NEW
    store.save_run(_run(SSH_OLD, cve_source="NVD cache (synced 2026-11-22)"))
    assert _status(store) == Status.NEW


def test_port_the_profile_did_not_scan_changes_nothing(store: Storage) -> None:
    store.save_run(_run(MYSQL, findings=[_finding(MYSQL, "CVE-2024-21236")]))
    store.save_run(_run(SSH_OLD, profile=QUICK))  # top-100: 3306 may not be in it
    assert _status(store) == Status.NEW
    services = {s["port"]: s["state"] for s in store.inventory_hosts()[0]["services"]}
    assert services[3306] == "open"  # not concluded closed either


def test_same_profile_and_port_gone_means_closed_and_gone(store: Storage) -> None:
    store.save_run(_run(MYSQL, findings=[_finding(MYSQL, "CVE-2024-21236")]))
    store.save_run(_run(SSH_OLD))  # same standard profile: 3306 was scanned, is closed
    assert _status(store) == Status.GONE
    services = {s["port"]: s["state"] for s in store.inventory_hosts()[0]["services"]}
    assert services == {3306: "closed", 22: "open"}


def test_failed_run_changes_nothing(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(status=RunStatus.FAILED, answered=False))
    assert _status(store) == Status.NEW
    assert store.inventory_hosts()[0]["state"] == "up"


def test_accepted_risk_needs_reason_and_date_and_expires(store: Storage) -> None:
    issue = _finding(SSH_OLD)
    store.save_run(_run(SSH_OLD, findings=[issue], day=1))
    (row,) = store.inventory_findings()
    on_day_2 = "2026-11-02T09:00:00+00:00"  # decisions are dated; no test reads the clock
    with pytest.raises(InventoryError, match="needs a reason"):
        store.decide_finding(row.id, "accept", actor="bob", until="2099-01-01")
    with pytest.raises(InventoryError, match="review date"):
        store.decide_finding(row.id, "accept", actor="bob", note="legacy box")
    with pytest.raises(InventoryError, match="in the future"):
        store.decide_finding(
            row.id, "accept", actor="bob", note="x", until="2026-11-02", at=on_day_2
        )
    store.decide_finding(
        row.id, "accept", actor="bob", note="isolated VLAN", until="2026-11-10", at=on_day_2
    )
    store.save_run(_run(SSH_OLD, findings=[issue], day=5))
    assert _status(store) == Status.ACCEPTED  # still within the acceptance
    store.save_run(_run(SSH_OLD, findings=[issue], day=12))
    assert _status(store) == Status.OPEN  # the review date passed
    assert _events(store)[-1] == "acceptance_expired"
    assert store.decide_finding(row.id, "reopen", actor="bob") == Status.OPEN


def test_cannot_claim_what_is_not_open(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(SSH_NEW))
    (row,) = store.inventory_findings()
    with pytest.raises(InventoryError, match="nothing to claim"):
        store.decide_finding(row.id, "claim_fixed", actor="bob")
    with pytest.raises(InventoryError, match="no finding #99"):
        store.decide_finding(99, "reopen", actor="bob")


def test_old_fingerprints_are_not_inventoried(store: Storage) -> None:
    legacy = _finding(SSH_OLD)
    legacy.fingerprint = "a" * 64  # scheme 1: no "v2:" prefix
    store.save_run(_run(SSH_OLD, findings=[legacy]))
    assert store.inventory_findings() == []
    assert len(store.inventory_hosts()) == 1


def test_rebuild_replays_the_runs(store: Storage) -> None:
    store.save_run(_run(SSH_OLD, findings=[_finding(SSH_OLD)]))
    store.save_run(_run(SSH_NEW))
    store._conn.execute("DELETE FROM inv_finding")
    store._conn.commit()
    assert store.rebuild_inventory() == 2
    assert _status(store) == Status.GONE
    assert _events(store) == ["new", "gone"]


# --- diffs ---------------------------------------------------------------------------------------


def test_diff_between_two_runs() -> None:
    issue = _finding(SSH_OLD)
    before = _run(SSH_OLD, MYSQL, findings=[issue], day=1)
    other = Asset(host="10.0.0.7", ip="10.0.0.7", services=[Service(port=80, name="http")])
    after = _run(SSH_NEW, Service(port=443, name="https"), day=2)
    after.assets.append(other)
    d = diff_runs(before, after)
    assert d.hosts_added == ["10.0.0.7"]
    assert [(h, s.port) for h, s in d.services_added] == [("10.0.0.5", 443)]
    assert [(h, s.port) for h, s in d.services_removed] == [("10.0.0.5", 3306)]
    assert [(c.port, c.before, c.after) for c in d.services_changed] == [
        (22, "ssh OpenSSH 7.4", "ssh OpenSSH 9.9")
    ]
    assert [f.cve for _, f in d.findings_removed] == ["CVE-2018-15473"]
    assert d.caveats == [] and not d.empty
    assert diff_runs(before, before).empty


def test_diff_says_when_runs_are_not_comparable() -> None:
    before = _run(SSH_OLD, day=1)
    after = _run(SSH_OLD, profile=QUICK, cve_source=None, day=2)
    after.target = "10.0.0.5"
    caveats = " | ".join(diff_runs(before, after).caveats)
    assert "different targets" in caveats
    assert "different scan profiles" in caveats
    assert "different CVE data" in caveats


# --- CLI -----------------------------------------------------------------------------------------


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Scan "scanme.lab" with whatever services the test puts in `lab["services"]`."""
    from conftest import FakePlugin, lab_asset, lab_resolver

    from zues_scan import cli

    state: dict[str, Any] = {"services": [SSH_OLD]}
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr(
        "zues_scan.plugins.registry.NmapPlugin",
        lambda **_: FakePlugin([lab_asset(*state["services"])]),
    )
    scope = tmp_path / "scope.txt"
    scope.write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
    db = str(tmp_path / "out.db")
    state["db"] = db
    state["scan"] = lambda: cli.main(["scan", "scanme.lab", "--scope", str(scope), "--db", db])
    state["cli"] = cli
    return state


def test_cli_lifecycle_from_scan_to_fake_fix(
    lab: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    cli, db = lab["cli"], lab["db"]
    assert lab["scan"]() == 0
    assert "inventory: 1 new" in capsys.readouterr().out

    assert cli.main(["findings", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "   1  new" in out and "CVE-2018-15473" in out and "10.0.0.5" in out

    assert cli.main(["finding", "1", "--db", db, "--claim-fixed", "--operator", "bob"]) == 0
    assert "now fix_claimed" in capsys.readouterr().out
    assert lab["scan"]() == 0  # nothing was changed on the machine
    out = capsys.readouterr().out
    assert "ALERT FAKE FIX: claimed fixed, still there: finding #1" in out

    assert cli.main(["finding", "1", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "status: fake_fix" in out
    assert "new -> fix_claimed  [fix_claimed] by bob" in out
    assert "fix_claimed -> fake_fix  [fake_fix] (run #2)" in out

    lab["services"] = [SSH_NEW]  # really fixed this time
    cli.main(["finding", "1", "--db", db, "--claim-fixed"])
    lab["scan"]()
    assert "verified fixed: finding #1" in capsys.readouterr().out
    assert cli.main(["findings", "--db", db]) == 0
    assert "no finding with that status" in capsys.readouterr().out
    assert cli.main(["findings", "--db", db, "--status", "fixed"]) == 0
    assert "   1  fixed" in capsys.readouterr().out


def test_cli_accept_needs_a_reason(lab: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    cli, db = lab["cli"], lab["db"]
    lab["scan"]()
    capsys.readouterr()
    assert cli.main(["finding", "1", "--db", db, "--accept", "--until", "2099-01-01"]) == 2
    assert "needs a reason" in capsys.readouterr().err
    argv = ["finding", "1", "--db", db, "--accept", "--reason", "isolated", "--until", "2099-01-01"]
    assert cli.main(argv) == 0
    assert cli.main(["finding", "7", "--db", db]) == 1


def test_cli_inventory_and_diff(lab: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    cli, db = lab["cli"], lab["db"]
    lab["scan"]()
    lab["services"] = [SSH_NEW, Service(port=443, name="https")]
    lab["scan"]()
    capsys.readouterr()

    assert cli.main(["inventory", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "scanme.lab (10.0.0.5)  [up]" in out
    assert "443/tcp  https" in out and "22/tcp  ssh" in out and "OpenSSH 9.9" in out

    assert cli.main(["diff", "--db", db]) == 0  # the last run and the one before it
    out = capsys.readouterr().out
    assert "run #1" in out and "-> run #2" in out
    assert "+ scanme.lab (10.0.0.5) 443/tcp https" in out
    assert "~ scanme.lab (10.0.0.5) 22/tcp: ssh OpenSSH 7.4 -> ssh OpenSSH 9.9" in out
    assert "- finding on scanme.lab (10.0.0.5): CVE-2018-15473" in out
    assert cli.main(["diff", "2", "2", "--db", db]) == 0
    assert "no change" in capsys.readouterr().out

    assert cli.main(["inventory", "--db", db, "--rebuild"]) == 0
    assert "rebuilt from 2 run(s)" in capsys.readouterr().out


def test_report_shows_lifecycle_and_changes(
    lab: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import json
    import re

    cli, db = lab["cli"], lab["db"]
    lab["scan"]()
    cli.main(["finding", "1", "--db", db, "--claim-fixed"])
    lab["scan"]()
    out = tmp_path / "r.html"
    assert cli.main(["report", "--db", db, "--html", str(out)]) == 0
    page = out.read_text(encoding="utf-8")
    data = json.loads(re.search(r'id="zues-data">(.*?)</script>', page, re.S).group(1))  # type: ignore[union-attr]
    assert data["changes"][0]["event"] == "fake_fix"
    assert data["hosts"][0]["findings"][0]["status"] == "fake_fix"
