"""Data written while the project was called ReconKit keeps working under ZuesScan."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from zues_scan import backup
from zues_scan.cve.records import load_records
from zues_scan.plugins.nuclei import templates_version
from zues_scan.storage import Storage

SEED = Path(__file__).parent.parent / "zues_scan" / "data" / "cve_seed.json"


def test_cve_data_in_the_old_format_still_loads(tmp_path: Path) -> None:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    assert data["format"] == "zues-cve"  # what is written now
    data["format"] = "reconkit-cve"  # a file written before the rename
    old = tmp_path / "old.json"
    old.write_text(json.dumps(data), encoding="utf-8")
    assert load_records(old) == load_records(SEED)


def test_templates_installed_before_the_rename_keep_their_version(tmp_path: Path) -> None:
    (tmp_path / ".reconkit-version").write_text("10.5.2\n", encoding="utf-8")
    assert templates_version(str(tmp_path)) == "10.5.2"
    (tmp_path / ".zues-version").write_text("10.6.0\n", encoding="utf-8")
    assert templates_version(str(tmp_path)) == "10.6.0"  # the current name wins


def test_old_backups_are_rotated_too(tmp_path: Path) -> None:
    for name in ("reconkit-20261101T000000Z.db", "zues-20261201T000000Z.db", "notes.db"):
        (tmp_path / name).write_bytes(b"x")
    assert backup.rotate(tmp_path, keep=1) == ["reconkit-20261101T000000Z.db"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["notes.db", "zues-20261201T000000Z.db"]


def test_the_database_keeps_its_column(tmp_path: Path) -> None:
    db = tmp_path / "zues.db"
    with Storage(db):
        pass
    columns = {row[1] for row in sqlite3.connect(db).execute("PRAGMA table_info(scan_run)")}
    # Renaming the column would need a migration and break every existing database.
    assert "reconkit_version" in columns and "zues_version" not in columns
