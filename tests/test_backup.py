"""Backups: a consistent copy, checked, with its hash recorded; old ones rotated."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver

from zues_scan import backup as backups
from zues_scan import cli
from zues_scan.schema import Service
from zues_scan.storage import SCHEMA_VERSION, Storage


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A database with one real (fake-scanner) run, saved through the CLI."""
    monkeypatch.setattr("zues_scan.scope.resolve_ipv4", lab_resolver)
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    fake = FakePlugin([lab_asset(Service(port=21, product="vsftpd", version="2.3.4"))])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: fake)
    scope = tmp_path / "scope.txt"
    scope.write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
    path = tmp_path / "zues.db"
    assert cli.main(["scan", "scanme.lab", "--scope", str(scope), "--db", str(path)]) == 0
    return path


def test_a_backup_is_a_checked_copy_with_its_hash(db: Path, tmp_path: Path) -> None:
    made = backups.backup(db, tmp_path / "out")

    check = made.check
    assert check.ok, check.problems
    copy = Path(check.path)
    assert re.fullmatch(r"zues-\d{8}T\d{6}Z\.db", copy.name)
    assert (check.runs, check.schema_version) == (1, SCHEMA_VERSION)
    assert check.audit_events == 1 and check.audit_head is not None
    sidecar = copy.with_name(copy.name + ".sha256").read_text(encoding="utf-8")
    assert sidecar == f"{check.sha256}  {copy.name}\n"  # sha256sum -c reads this
    with Storage(db) as store:
        assert store.verify_audit().head == check.audit_head  # the same history
    assert not list((tmp_path / "out").glob("*.partial"))


def test_a_backup_never_creates_or_changes_the_source(tmp_path: Path) -> None:
    with pytest.raises(backups.BackupError, match="database not found"):
        backups.backup(tmp_path / "missing.db", tmp_path / "out")
    assert not (tmp_path / "missing.db").exists()


def test_verify_catches_a_changed_backup(db: Path, tmp_path: Path) -> None:
    check = backups.backup(db, tmp_path / "out").check
    assert backups.verify(check.path).ok

    copy = Path(check.path)
    with Storage(copy) as store:  # someone edits the copy: a run "never happened"
        store._conn.execute("UPDATE audit_event SET target = 'elsewhere'")
        store._conn.commit()

    problems = backups.verify(copy).problems
    assert "the file's SHA-256 differs from the one recorded at backup" in problems
    assert any(p.startswith("audit: event #1") for p in problems)


def test_verify_needs_the_recorded_hash(db: Path, tmp_path: Path) -> None:
    copy = Path(backups.backup(db, tmp_path / "out").check.path)
    copy.with_name(copy.name + ".sha256").unlink()
    [problem] = backups.verify(copy).problems
    assert problem.startswith("no zues-") and "cannot be compared" in problem


def test_verify_rejects_what_is_not_a_zues_database(tmp_path: Path) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database at all" * 100)
    assert any("not a readable SQLite" in p for p in backups.verify(junk).problems)


def test_rotation_keeps_the_newest_and_touches_nothing_else(db: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
        (out / f"zues-{stamp}.db").write_bytes(b"old")
        (out / f"zues-{stamp}.db.sha256").write_text("x", encoding="utf-8")
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    (out / "zues-manual.db").write_bytes(b"mine too")

    made = backups.backup(db, out, keep=2)

    assert made.removed == [
        "zues-20260101T000000Z.db",
        "zues-20260102T000000Z.db",
    ]
    left = sorted(p.name for p in out.iterdir())
    assert left == sorted(
        [
            "notes.txt",
            "zues-manual.db",
            "zues-20260103T000000Z.db",
            "zues-20260103T000000Z.db.sha256",
            Path(made.check.path).name,
            Path(made.check.path).name + ".sha256",
        ]
    )


def test_cli_backup_and_verify(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    assert cli.main(["backup", "--db", str(db), "--out-dir", str(out), "--keep", "5"]) == 0
    text = capsys.readouterr().out
    assert "backup written: " in text and "1 run(s)" in text
    assert "audit trail: 1 event(s), head " in text and "keep that head hash" in text
    [copy] = out.glob("*.db")

    assert cli.main(["backup", "--verify", str(copy)]) == 0
    assert "backup checked: " in capsys.readouterr().out

    os.chmod(copy, 0o600)
    copy.write_bytes(copy.read_bytes()[:-10] + b"0123456789")  # a damaged copy
    assert cli.main(["backup", "--verify", str(copy)]) == 1
    assert "PROBLEM: the file's SHA-256 differs" in capsys.readouterr().err

    assert cli.main(["backup", "--db", str(tmp_path / "none.db")]) == 2
    assert cli.main(["backup", "--db", str(db), "--keep", "0"]) == 2


def test_a_backup_is_one_file_and_holds_what_the_log_still_has(db: Path, tmp_path: Path) -> None:
    with Storage(db) as live:  # a service keeps it open: recent writes sit in the -wal
        assert live.journal_mode() == "wal"
        live.record_refusal(
            "10.9.9.9", "not in the scope", operator="alice", engagement=None, scope_sha256=None
        )
        made = backups.backup(db, tmp_path / "out")

    copy = Path(made.check.path)
    header = copy.read_bytes()[18:20]
    assert header == b"\x01\x01"  # rollback-journal mode: nothing else is needed
    assert not copy.with_name(copy.name + "-wal").exists()
    assert made.check.ok and made.check.audit_events == 2  # the refusal is in it
    assert backups.verify(copy).ok
