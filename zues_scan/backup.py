"""Backups of the ZuesScan database: consistent while the service runs, and checked.

`backup()` copies the database with SQLite's online backup API (a consistent snapshot
even while the worker writes, unlike copying the file), checks the copy
(`PRAGMA integrity_check`, the audit trail's hash chain), writes its SHA-256 next to
it in `sha256sum` format, and can keep only the newest N backups. `verify()` checks a
backup again before it is restored.

The source is opened read-only: a backup never creates, migrates or changes it.
Standard library only.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from zues_scan.storage import SCHEMA_VERSION, Storage, StorageError

PREFIX = "zues-"
# Backups made before the project was renamed (reconkit-...) are rotated too.
_NAME = re.compile(r"(?:zues|reconkit)-\d{8}T\d{6}Z\.db")


class BackupError(Exception):
    """The backup could not be made, or a backup is not usable."""


@dataclass
class Check:
    """What a backup file holds, and whether it is sound."""

    path: str
    sha256: str
    size: int
    schema_version: int
    runs: int
    audit_events: int | None  # None: the audit trail was not checked (other schema)
    audit_head: str | None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass
class Backup:
    check: Check
    removed: list[str] = field(default_factory=list)  # older backups rotated out


def backup(db: str | Path, out_dir: str | Path, keep: int | None = None) -> Backup:
    """Copy `db` into `out_dir` as zues-<UTC time>.db, check it, rotate old ones."""
    source = Path(db)
    if not source.is_file():
        raise BackupError(f"database not found: {db}")
    if keep is not None and keep < 1:
        raise BackupError("--keep must be at least 1")
    folder = Path(out_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = folder / f"{PREFIX}{stamp}.db"
    if target.exists():
        raise BackupError(f"{target} already exists (two backups in the same second)")
    partial = target.with_suffix(".db.partial")
    try:
        src = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
        try:
            dest = sqlite3.connect(partial)
            try:
                src.backup(dest)  # reads what the write-ahead log holds too
                # The copy is one self-contained file (no -wal beside it), whatever the
                # live database's mode: what its SHA-256 covers is all there is.
                dest.execute("PRAGMA journal_mode = DELETE")
            finally:
                dest.close()
        finally:
            src.close()
    except sqlite3.Error as exc:
        partial.unlink(missing_ok=True)
        raise BackupError(f"cannot back up {db}: {exc}") from exc
    partial.replace(target)  # only a complete copy ever carries the final name

    result = inspect(target)
    if not result.ok:
        # Keep it for inspection, but say so loudly: this is not a usable backup.
        raise BackupError(f"the backup {target} failed its checks: {'; '.join(result.problems)}")
    target.with_name(target.name + ".sha256").write_text(
        f"{result.sha256}  {target.name}\n", encoding="utf-8", newline="\n"
    )
    removed = rotate(folder, keep) if keep is not None else []
    return Backup(result, removed)


def verify(path: str | Path) -> Check:
    """Check a backup: its recorded SHA-256, SQLite's integrity check, the audit chain."""
    file = Path(path)
    if not file.is_file():
        raise BackupError(f"backup not found: {path}")
    result = inspect(file)
    sidecar = file.with_name(file.name + ".sha256")
    if not sidecar.is_file():
        result.problems.append(f"no {sidecar.name}: the file cannot be compared with its record")
    else:
        recorded = sidecar.read_text(encoding="utf-8").split()
        if not recorded or recorded[0].lower() != result.sha256:
            result.problems.append("the file's SHA-256 differs from the one recorded at backup")
    return result


def inspect(path: Path) -> Check:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    check = Check(str(path), digest, path.stat().st_size, 0, 0, None, None)
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            result = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
            if result != ["ok"]:
                check.problems.extend(f"integrity: {line}" for line in result[:5])
                return check
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
            if "scan_run" not in tables:
                check.problems.append("not a ZuesScan database (no scan_run table)")
                return check
            if "schema_version" in tables:
                row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
                check.schema_version = int(row[0] or 0)
            else:
                check.schema_version = 1
            check.runs = int(conn.execute("SELECT COUNT(*) FROM scan_run").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error as exc:
        check.problems.append(f"not a readable SQLite database: {exc}")
        return check
    if check.schema_version == SCHEMA_VERSION:
        # Same schema as this version: Storage opens it without changing anything.
        try:
            with Storage(path) as store:
                report = store.verify_audit()
        except StorageError as exc:
            check.problems.append(str(exc))
            return check
        check.audit_events, check.audit_head = report.events, report.head
        check.problems.extend(f"audit: {p}" for p in report.problems)
    return check


def rotate(folder: Path, keep: int) -> list[str]:
    """Delete all but the `keep` newest backups ZuesScan made in `folder`."""
    ours = sorted(p for p in folder.iterdir() if _NAME.fullmatch(p.name))
    removed = []
    for old in ours[:-keep]:
        old.unlink()
        old.with_name(old.name + ".sha256").unlink(missing_ok=True)
        removed.append(old.name)
    return removed
