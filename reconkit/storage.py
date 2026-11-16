"""SQLite persistence via a thin repository.

One `scan_run` (with all its assets, services and findings) is written inside a single
transaction, so a crash mid-write rolls back cleanly rather than leaving half a scan
in the database (GHI-CHU.md section 6). The repository hides SQL behind methods, so
swapping SQLite for PostgreSQL later is a storage-layer change only.

The schema is versioned. Opening a database brings it up to `SCHEMA_VERSION` by
applying, in order, the migrations it has not seen yet; the `schema_version` table
records each one. A fresh database simply starts at version 0 and takes the same path,
so there is one way to build the schema and every migration is exercised by every test.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from reconkit.orchestrator import RunStatus, ScanRun
from reconkit.schema import Asset, Finding, Service, Severity

# The schema version this code reads and writes. Bump it together with a new entry
# in `_MIGRATIONS`; never edit a migration that has already shipped.
SCHEMA_VERSION = 2


class StorageError(Exception):
    """The database cannot be used: unreadable, inconsistent, or from a newer ReconKit."""


# Version 1: the tables of the first vertical slice, exactly as they shipped.
_V1 = (
    """
    CREATE TABLE scan_run (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target      TEXT NOT NULL,
        started_at  TEXT NOT NULL,
        finished_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE asset (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id  INTEGER NOT NULL REFERENCES scan_run(id),
        host    TEXT NOT NULL,
        ip      TEXT
    )
    """,
    """
    CREATE TABLE service (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id  INTEGER NOT NULL REFERENCES asset(id),
        port      INTEGER NOT NULL,
        protocol  TEXT NOT NULL,
        state     TEXT NOT NULL,
        name      TEXT,
        product   TEXT,
        version   TEXT,
        cpe       TEXT,
        banner    TEXT
    )
    """,
    """
    CREATE TABLE finding (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id    INTEGER NOT NULL REFERENCES asset(id),
        title       TEXT NOT NULL,
        severity    TEXT NOT NULL,
        cve         TEXT,
        description TEXT,
        evidence    TEXT,
        fingerprint TEXT NOT NULL
    )
    """,
    "CREATE INDEX idx_finding_fingerprint ON finding(fingerprint)",
)

# Version 2 (F7): run status / error / tool versions (G14), finding -> service link
# (G5), ON DELETE CASCADE + indexes on every foreign key (G15).
#
# SQLite cannot add a constraint to an existing table, so each table is rebuilt:
# create the new shape, copy the rows over, drop the old table, rename the new one.
# Ids are copied as they are, so every reference between rows stays valid.
_V2 = (
    # --- scan_run: + status, error, reconkit_version ---------------------------------
    """
    CREATE TABLE scan_run_new (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        target           TEXT NOT NULL,
        status           TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'failed')),
        error            TEXT,
        started_at       TEXT NOT NULL,
        finished_at      TEXT NOT NULL,
        reconkit_version TEXT
    )
    """,
    # Version 1 only ever stored scans that had succeeded.
    """
    INSERT INTO scan_run_new (id, target, status, started_at, finished_at)
    SELECT id, target, 'completed', started_at, finished_at FROM scan_run
    """,
    "DROP TABLE scan_run",
    "ALTER TABLE scan_run_new RENAME TO scan_run",
    # --- asset: + cascade ---------------------------------------------------------------
    """
    CREATE TABLE asset_new (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id  INTEGER NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
        host    TEXT NOT NULL,
        ip      TEXT
    )
    """,
    "INSERT INTO asset_new (id, run_id, host, ip) SELECT id, run_id, host, ip FROM asset",
    "DROP TABLE asset",
    "ALTER TABLE asset_new RENAME TO asset",
    "CREATE INDEX idx_asset_run ON asset(run_id)",
    # --- service: + cascade -------------------------------------------------------------
    """
    CREATE TABLE service_new (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id  INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
        port      INTEGER NOT NULL,
        protocol  TEXT NOT NULL,
        state     TEXT NOT NULL,
        name      TEXT,
        product   TEXT,
        version   TEXT,
        cpe       TEXT,
        banner    TEXT
    )
    """,
    """
    INSERT INTO service_new
        (id, asset_id, port, protocol, state, name, product, version, cpe, banner)
    SELECT id, asset_id, port, protocol, state, name, product, version, cpe, banner
    FROM service
    """,
    "DROP TABLE service",
    "ALTER TABLE service_new RENAME TO service",
    "CREATE INDEX idx_service_asset ON service(asset_id)",
    # --- finding: + service_id, cascade -------------------------------------------------
    # Deleting a service must not silently delete what was found on it: SET NULL.
    """
    CREATE TABLE finding_new (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
        service_id  INTEGER REFERENCES service(id) ON DELETE SET NULL,
        title       TEXT NOT NULL,
        severity    TEXT NOT NULL,
        cve         TEXT,
        description TEXT,
        evidence    TEXT,
        fingerprint TEXT NOT NULL
    )
    """,
    # Version 1 never recorded which service a finding was on; it stays unknown (NULL)
    # rather than being guessed.
    """
    INSERT INTO finding_new
        (id, asset_id, title, severity, cve, description, evidence, fingerprint)
    SELECT id, asset_id, title, severity, cve, description, evidence, fingerprint
    FROM finding
    """,
    "DROP TABLE finding",
    "ALTER TABLE finding_new RENAME TO finding",
    "CREATE INDEX idx_finding_asset ON finding(asset_id)",
    "CREATE INDEX idx_finding_service ON finding(service_id)",
    "CREATE INDEX idx_finding_fingerprint ON finding(fingerprint)",
    # --- new: what each scanner did in a run, and with which version ------------------
    """
    CREATE TABLE scan_run_plugin (
        run_id   INTEGER NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
        name     TEXT NOT NULL,
        status   TEXT NOT NULL CHECK (status IN ('ran', 'skipped', 'failed')),
        version  TEXT,
        PRIMARY KEY (run_id, name)
    )
    """,
    # --- new: hosts a scanner reported that the scope guard threw away ----------------
    """
    CREATE TABLE scan_run_out_of_scope (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id  INTEGER NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
        host    TEXT NOT NULL
    )
    """,
    "CREATE INDEX idx_out_of_scope_run ON scan_run_out_of_scope(run_id)",
)

_MIGRATIONS: dict[int, tuple[str, ...]] = {1: _V1, 2: _V2}


class Storage:
    """A SQLite-backed repository for scan results."""

    def __init__(self, path: str | Path = "reconkit.db") -> None:
        self.path = str(path)
        # Set when opening this database upgraded an older one: where its copy is.
        self.backup_path: str | None = None
        try:
            self._conn = sqlite3.connect(self.path)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            self._migrate()
            self._conn.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error as exc:
            self._conn.close()
            raise StorageError(f"cannot use database {self.path}: {exc}") from exc
        except StorageError:
            self._conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- schema versioning -------------------------------------------------------------

    def schema_version(self) -> int:
        """The version of the schema in this database (0 = empty database)."""
        tables = {
            r["name"]
            for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "schema_version" in tables:
            row = self._conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            return int(row["v"] or 0)
        # Version 1 shipped before the schema was versioned: recognise it by its tables.
        return 1 if "scan_run" in tables else 0

    def _migrate(self) -> None:
        """Bring the database up to `SCHEMA_VERSION`, all or nothing."""
        current = self.schema_version()
        if current > SCHEMA_VERSION:
            # Never touch data written by a newer version: we could corrupt it.
            raise StorageError(
                f"database {self.path} has schema v{current}, but this ReconKit only "
                f"understands up to v{SCHEMA_VERSION}; upgrade ReconKit"
            )
        if current == SCHEMA_VERSION:
            return
        if current > 0:
            self._backup(current)

        conn = self._conn
        # Rebuilding a table drops it for a moment; with foreign keys enforced, that
        # would cascade into its children. The switch is ignored inside a transaction,
        # so it is flipped before BEGIN (and back on by the caller).
        conn.execute("PRAGMA foreign_keys = OFF")
        # IMMEDIATE takes the write lock now: two processes cannot migrate at once.
        conn.execute("BEGIN IMMEDIATE")
        try:
            current = self.schema_version()  # again, now that we hold the lock
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for statement in _MIGRATIONS[version]:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(UTC).isoformat()),
                )
            # Foreign keys were off during the rebuild: prove no row lost its parent.
            broken = conn.execute("PRAGMA foreign_key_check").fetchall()
            if broken:
                raise StorageError(
                    f"migrating {self.path} to schema v{SCHEMA_VERSION} would leave "
                    f"{len(broken)} row(s) pointing at missing rows; nothing was changed"
                )
            conn.commit()
        except BaseException:
            conn.rollback()  # DDL is transactional in SQLite: the old schema is intact
            raise

    def _backup(self, version: int) -> None:
        """Copy the database aside before changing its schema."""
        if self.path == ":memory:":
            return
        backup_path = f"{self.path}.v{version}.bak"
        target = sqlite3.connect(backup_path)
        try:
            self._conn.backup(target)  # a consistent snapshot, unlike copying the file
        finally:
            target.close()
        self.backup_path = backup_path

    # --- writing -----------------------------------------------------------------------

    def save_run(self, run: ScanRun) -> int:
        """Persist a whole scan run atomically; return the new run id."""
        with self._conn:  # BEGIN ... COMMIT, or ROLLBACK on exception
            cur = self._conn.execute(
                "INSERT INTO scan_run "
                "(target, status, error, started_at, finished_at, reconkit_version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run.target,
                    str(run.status),
                    run.error,
                    run.started_at,
                    run.finished_at,
                    run.reconkit_version,
                ),
            )
            run_id = int(cur.lastrowid or 0)
            self._insert_plugins(run_id, run)
            self._conn.executemany(
                "INSERT INTO scan_run_out_of_scope (run_id, host) VALUES (?, ?)",
                [(run_id, host) for host in run.out_of_scope],
            )
            for asset in run.assets:
                cur = self._conn.execute(
                    "INSERT INTO asset (run_id, host, ip) VALUES (?, ?, ?)",
                    (run_id, asset.host, asset.ip),
                )
                asset_id = int(cur.lastrowid or 0)
                service_ids = self._insert_services(asset_id, asset.services)
                self._insert_findings(asset_id, asset.findings, service_ids)
        return run_id

    def _insert_plugins(self, run_id: int, run: ScanRun) -> None:
        # One row per scanner. Later states win: a scanner that ran and then failed
        # is recorded as failed, with the version it ran as.
        rows: dict[str, tuple[str, str | None]] = {}
        for name in run.skipped_plugins:
            rows[name] = ("skipped", None)
        for name, version in run.tool_versions.items():
            rows[name] = ("ran", version)
        if run.failed_plugin is not None:
            rows[run.failed_plugin] = ("failed", run.tool_versions.get(run.failed_plugin))
        self._conn.executemany(
            "INSERT INTO scan_run_plugin (run_id, name, status, version) VALUES (?, ?, ?, ?)",
            [(run_id, name, status, version) for name, (status, version) in rows.items()],
        )

    def _insert_services(
        self, asset_id: int, services: list[Service]
    ) -> dict[tuple[int, str], int]:
        """Insert the services of one asset; return the row id of each (port, protocol)."""
        ids: dict[tuple[int, str], int] = {}
        for s in services:
            cur = self._conn.execute(
                "INSERT INTO service "
                "(asset_id, port, protocol, state, name, product, version, cpe, banner) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    asset_id,
                    s.port,
                    s.protocol,
                    s.state,
                    s.name,
                    s.product,
                    s.version,
                    s.cpe,
                    s.banner,
                ),
            )
            ids[(s.port, s.protocol)] = int(cur.lastrowid or 0)
        return ids

    def _insert_findings(
        self, asset_id: int, findings: list[Finding], service_ids: dict[tuple[int, str], int]
    ) -> None:
        rows = []
        for f in findings:
            fp = f.fingerprint or f.compute_fingerprint()
            # A port is one service on a host, whichever tool reported the finding.
            service_id = (
                service_ids.get((f.service.port, f.service.protocol)) if f.service else None
            )
            rows.append(
                (
                    asset_id,
                    service_id,
                    f.title,
                    str(f.severity),
                    f.cve,
                    f.description,
                    f.evidence,
                    fp,
                )
            )
        self._conn.executemany(
            "INSERT INTO finding "
            "(asset_id, service_id, title, severity, cve, description, evidence, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def delete_run(self, run_id: int) -> bool:
        """Delete a run and everything recorded for it; False if there is no such run."""
        with self._conn:
            cur = self._conn.execute("DELETE FROM scan_run WHERE id = ?", (run_id,))
        return cur.rowcount > 0

    # --- reading -----------------------------------------------------------------------

    def load_run(self, run_id: int) -> ScanRun | None:
        """Read a whole run back, as it was saved; None if there is no such run.

        `plan` (what the scope guard authorised) is not stored yet, so it comes back
        as None — see G21.
        """
        row = self._conn.execute(
            "SELECT target, status, error, started_at, finished_at, reconkit_version "
            "FROM scan_run WHERE id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        run = ScanRun(
            target=row["target"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            status=RunStatus(row["status"]),
            error=row["error"],
            reconkit_version=row["reconkit_version"],
        )
        for p in self._conn.execute(
            "SELECT name, status, version FROM scan_run_plugin WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        ):
            if p["status"] == "skipped":
                run.skipped_plugins.append(p["name"])
                continue
            run.tool_versions[p["name"]] = p["version"]
            if p["status"] == "failed":
                run.failed_plugin = p["name"]
        run.out_of_scope = [
            r["host"]
            for r in self._conn.execute(
                "SELECT host FROM scan_run_out_of_scope WHERE run_id = ? ORDER BY id", (run_id,)
            )
        ]

        services_by_id: dict[int, Service] = {}
        for a in self._conn.execute(
            "SELECT id, host, ip FROM asset WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall():
            asset = Asset(host=a["host"], ip=a["ip"])
            for s in self._conn.execute(
                "SELECT id, port, protocol, state, name, product, version, cpe, banner "
                "FROM service WHERE asset_id = ? ORDER BY id",
                (a["id"],),
            ):
                service = _service(s)
                services_by_id[s["id"]] = service
                asset.services.append(service)
            for f in self._conn.execute(
                "SELECT service_id, title, severity, cve, description, evidence, fingerprint "
                "FROM finding WHERE asset_id = ? ORDER BY id",
                (a["id"],),
            ):
                asset.findings.append(_finding(f, a["host"], services_by_id.get(f["service_id"])))
            run.assets.append(asset)
        return run

    def services_for_run(self, run_id: int) -> list[Service]:
        """The services recorded for a run, across all its hosts, by port."""
        rows = self._conn.execute(
            "SELECT s.port, s.protocol, s.state, s.name, s.product, s.version, s.cpe, s.banner "
            "FROM service s JOIN asset a ON a.id = s.asset_id "
            "WHERE a.run_id = ? ORDER BY s.port, s.id",
            (run_id,),
        ).fetchall()
        return [_service(r) for r in rows]

    def findings_for_run(self, run_id: int) -> list[Finding]:
        """The findings recorded for a run, each with the service it was found on."""
        run = self.load_run(run_id)
        return [f for a in run.assets for f in a.findings] if run else []


def _service(row: sqlite3.Row) -> Service:
    return Service(
        port=row["port"],
        protocol=row["protocol"],
        state=row["state"],
        name=row["name"],
        product=row["product"],
        version=row["version"],
        cpe=row["cpe"],
        banner=row["banner"],
    )


def _finding(row: sqlite3.Row, host: str, service: Service | None) -> Finding:
    return Finding(
        asset=host,
        title=row["title"],
        severity=Severity(row["severity"]),
        service=service,
        cve=row["cve"],
        description=row["description"] or "",
        evidence=row["evidence"] or "",
        fingerprint=row["fingerprint"],
    )
