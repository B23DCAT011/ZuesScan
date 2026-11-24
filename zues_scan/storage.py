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

import json
import logging
import sqlite3
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zues_scan import inventory_store
from zues_scan.audit import GENESIS, AuditEvent, AuditKind, ChainReport, chain_hash
from zues_scan.inventory import Status
from zues_scan.inventory_store import FindingEvent, FindingRow
from zues_scan.orchestrator import RunStatus, ScanRun
from zues_scan.schema import (
    Asset,
    Confidence,
    Finding,
    Hop,
    RawOutput,
    ScanTarget,
    Service,
    Severity,
    WebPage,
)

log = logging.getLogger(__name__)

# The schema version this code reads and writes. Bump it together with a new entry
# in `_MIGRATIONS`; never edit a migration that has already shipped.
SCHEMA_VERSION = 15


class StorageError(Exception):
    """The database cannot be used: unreadable, inconsistent, or from a newer ZuesScan."""


@dataclass(frozen=True, slots=True)
class RunSummary:
    """One line of the list of runs: what was scanned, how it ended, how much it found."""

    id: int
    target: str
    status: RunStatus
    started_at: str
    finished_at: str
    hosts: int
    services: int
    findings: int


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
    # --- scan_run: + status, error, reconkit_version --------------------------------
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

# Version 3 (F8): a finding can carry the id of the check that produced it (G12).
# Adding a nullable column needs no rebuild.
#
# Fingerprints already stored are left as they are: they were made with scheme 1
# (title + product + version), carry no "v2:" prefix, and cannot be converted for
# rows that never recorded their service. Runs from before this version are therefore
# not comparable, by fingerprint, with runs after it.
_V3 = ("ALTER TABLE finding ADD COLUMN rule_id TEXT",)

# Version 4 (F9): the raw output of each scanner, kept as evidence (G13).
# `content` is zlib-compressed (scanner XML shrinks about tenfold); `sha256` and `size`
# describe the *uncompressed* text, so the evidence can be checked after reading.
_V4 = (
    """
    CREATE TABLE scan_run_output (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id   INTEGER NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
        plugin   TEXT NOT NULL,
        format   TEXT NOT NULL,
        command  TEXT NOT NULL,
        stderr   TEXT NOT NULL DEFAULT '',
        size     INTEGER NOT NULL,
        sha256   TEXT NOT NULL,
        content  BLOB NOT NULL
    )
    """,
    "CREATE INDEX idx_output_run ON scan_run_output(run_id)",
)

# Version 5 (M1): the network path to each host, as traceroute saw it — the routers
# between the scanner and the host, for the attack-surface map. A hop belongs to the
# asset of one run: the path can change from one scan to the next.
_V5 = (
    """
    CREATE TABLE route_hop (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id  INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
        ttl       INTEGER NOT NULL CHECK (ttl > 0),
        ip        TEXT,
        rtt_ms    REAL,
        name      TEXT,
        UNIQUE (asset_id, ttl)  -- one router per distance; also indexes asset_id
    )
    """,
)

# Version 6 (G6, G7): the scan profile of each run, by name and with its exact settings
# (JSON), so that two runs can be compared only when they looked at the same things.
_V6 = (
    "ALTER TABLE scan_run ADD COLUMN profile TEXT",
    "ALTER TABLE scan_run ADD COLUMN profile_settings TEXT",
)

# Version 7 (G10): how sure each finding is (tentative / firm / confirmed). Findings
# stored before it did not say: NULL, not a guess.
_V7 = (
    "ALTER TABLE finding ADD COLUMN confidence TEXT "
    "CHECK (confidence IN ('tentative', 'firm', 'confirmed'))",
)

# Version 8 (G11): the risk facts of a finding — CVSS, CWE, KEV listing, EPSS — as they
# were when the run matched it (they change later; the run records what it knew).
_V8 = (
    "ALTER TABLE finding ADD COLUMN cvss_score REAL",
    "ALTER TABLE finding ADD COLUMN cvss_vector TEXT",
    "ALTER TABLE finding ADD COLUMN cwe TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE finding ADD COLUMN kev_added TEXT",
    "ALTER TABLE finding ADD COLUMN epss REAL",
)

# Version 9 (G22): notes about how a run went (e.g. "IPv6: no host answered"), as a
# JSON list.
_V9 = ("ALTER TABLE scan_run ADD COLUMN notes TEXT NOT NULL DEFAULT '[]'",)

# Version 10 (G21): the audit trail. Each run records who ran it, the engagement, the
# scope file (path + SHA-256; its content once per version in `scope_snapshot`) and the
# exact plan the scope guard authorised. `audit_event` is a hash chain of every scan,
# refusal and deletion (see zues_scan/audit.py); `prev_hash` is UNIQUE so that two
# writers can never fork the chain.
_V10 = (
    "ALTER TABLE scan_run ADD COLUMN plan TEXT",
    "ALTER TABLE scan_run ADD COLUMN operator TEXT",
    "ALTER TABLE scan_run ADD COLUMN engagement TEXT",
    "ALTER TABLE scan_run ADD COLUMN scope_path TEXT",
    "ALTER TABLE scan_run ADD COLUMN scope_sha256 TEXT",
    """
    CREATE TABLE scope_snapshot (
        sha256   TEXT PRIMARY KEY,
        content  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE audit_event (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        at            TEXT NOT NULL,
        kind          TEXT NOT NULL CHECK (kind IN ('scan', 'refused', 'deleted')),
        run_id        INTEGER REFERENCES scan_run(id) ON DELETE SET NULL,
        target        TEXT NOT NULL,
        operator      TEXT,
        engagement    TEXT,
        scope_sha256  TEXT,
        detail        TEXT NOT NULL,
        prev_hash     TEXT NOT NULL UNIQUE,
        hash          TEXT NOT NULL UNIQUE
    )
    """,
    "CREATE INDEX idx_audit_run ON audit_event(run_id)",
)

# Version 11 (D1): the inventory — every host, service and finding across runs, with
# first / last seen and, for findings, their status in the lifecycle — and each
# finding's history (`finding_event`). Runs record which CVE data they used. The
# audit trail also records people's decisions about findings ('finding' events), so
# its CHECK constraint is rebuilt (rows and hashes are copied unchanged).
_V11 = (
    "ALTER TABLE scan_run ADD COLUMN cve_source TEXT",
    """
    CREATE TABLE inv_host (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        key          TEXT NOT NULL UNIQUE,
        host         TEXT NOT NULL,
        ip           TEXT,
        first_seen   TEXT NOT NULL,
        last_seen    TEXT NOT NULL,
        first_run    INTEGER,
        last_run     INTEGER,
        state        TEXT NOT NULL CHECK (state IN ('up', 'not_responding')),
        state_since  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE inv_service (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id       INTEGER NOT NULL REFERENCES inv_host(id) ON DELETE CASCADE,
        port          INTEGER NOT NULL,
        protocol      TEXT NOT NULL,
        name          TEXT,
        product       TEXT,
        version       TEXT,
        first_seen    TEXT NOT NULL,
        last_seen     TEXT NOT NULL,
        last_run      INTEGER,
        seen_profile  TEXT,
        state         TEXT NOT NULL CHECK (state IN ('open', 'closed')),
        state_since   TEXT NOT NULL,
        UNIQUE (host_id, port, protocol)
    )
    """,
    """
    CREATE TABLE inv_finding (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint     TEXT NOT NULL UNIQUE,
        host_id         INTEGER NOT NULL REFERENCES inv_host(id) ON DELETE CASCADE,
        port            INTEGER,
        protocol        TEXT,
        cve             TEXT,
        rule_id         TEXT,
        title           TEXT NOT NULL,
        severity        TEXT NOT NULL,
        confidence      TEXT,
        cvss_score      REAL,
        kev_added       TEXT,
        epss            REAL,
        first_seen      TEXT NOT NULL,
        last_seen       TEXT NOT NULL,
        first_run       INTEGER,
        last_run        INTEGER,
        seen_profile    TEXT,
        seen_cve_kind   TEXT,
        status          TEXT NOT NULL CHECK (status IN ('new', 'open', 'fix_claimed', 'fixed',
                            'fake_fix', 'gone', 'reappeared', 'accepted')),
        status_since    TEXT NOT NULL,
        accepted_until  TEXT,
        note            TEXT
    )
    """,
    "CREATE INDEX idx_inv_finding_host ON inv_finding(host_id)",
    "CREATE INDEX idx_inv_finding_status ON inv_finding(status)",
    """
    CREATE TABLE finding_event (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id  INTEGER NOT NULL REFERENCES inv_finding(id) ON DELETE CASCADE,
        run_id      INTEGER,
        at          TEXT NOT NULL,
        event       TEXT NOT NULL,
        old_status  TEXT,
        new_status  TEXT NOT NULL,
        actor       TEXT,
        note        TEXT
    )
    """,
    "CREATE INDEX idx_finding_event_finding ON finding_event(finding_id)",
    "CREATE INDEX idx_finding_event_run ON finding_event(run_id)",
    """
    CREATE TABLE audit_event_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        at            TEXT NOT NULL,
        kind          TEXT NOT NULL CHECK (kind IN ('scan', 'refused', 'deleted', 'finding')),
        run_id        INTEGER REFERENCES scan_run(id) ON DELETE SET NULL,
        target        TEXT NOT NULL,
        operator      TEXT,
        engagement    TEXT,
        scope_sha256  TEXT,
        detail        TEXT NOT NULL,
        prev_hash     TEXT NOT NULL UNIQUE,
        hash          TEXT NOT NULL UNIQUE
    )
    """,
    "INSERT INTO audit_event_new SELECT * FROM audit_event",
    "DROP TABLE audit_event",
    "ALTER TABLE audit_event_new RENAME TO audit_event",
    "CREATE INDEX idx_audit_run ON audit_event(run_id)",
)

# Version 12: every name known to point at a host (discovered subdomains, virtual
# hosts), as a JSON list.
_V12 = ("ALTER TABLE asset ADD COLUMN names TEXT NOT NULL DEFAULT '[]'",)

# Version 13: what a web check (httpx) saw on a service — URL, status, title, server,
# technologies — as a JSON object (NULL: not a web service, or not looked at).
_V13 = ("ALTER TABLE service ADD COLUMN web TEXT",)

# Version 14: the configuration people edit in the dashboard — scopes (the text of a
# scope file), targets (their settings as JSON) and tokens (only the SHA-256) — next to
# what service.toml says. `managed_meta.version` grows with every change, so that the
# services see a change without restarting. Changes are audited: kind 'config'.
_V14 = (
    """
    CREATE TABLE managed_scope (
        name        TEXT PRIMARY KEY,
        content     TEXT NOT NULL,
        sha256      TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        updated_by  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE managed_target (
        name        TEXT PRIMARY KEY,
        settings    TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        updated_by  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE managed_token (
        name        TEXT PRIMARY KEY,
        sha256      TEXT NOT NULL UNIQUE,
        role        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        created_by  TEXT NOT NULL
    )
    """,
    "CREATE TABLE managed_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "INSERT INTO managed_meta (key, value) VALUES ('version', 0)",
    """
    CREATE TABLE audit_event_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        at            TEXT NOT NULL,
        kind          TEXT NOT NULL
                      CHECK (kind IN ('scan', 'refused', 'deleted', 'finding', 'config')),
        run_id        INTEGER REFERENCES scan_run(id) ON DELETE SET NULL,
        target        TEXT NOT NULL,
        operator      TEXT,
        engagement    TEXT,
        scope_sha256  TEXT,
        detail        TEXT NOT NULL,
        prev_hash     TEXT NOT NULL UNIQUE,
        hash          TEXT NOT NULL UNIQUE
    )
    """,
    "INSERT INTO audit_event_new SELECT * FROM audit_event",
    "DROP TABLE audit_event",
    "ALTER TABLE audit_event_new RENAME TO audit_event",
    "CREATE INDEX idx_audit_run ON audit_event(run_id)",
)

# Version 15: the dashboard's sessions, held by the server (G23). The browser's cookie is
# a random secret; only its SHA-256 is stored, with the token the session was opened with
# (revoking or re-issuing that token ends it), when it ends at the latest and when it was
# last used (an idle session ends too). Signing in and out, sessions ended by an admin
# and addresses locked out after failed sign-ins are audited: kind 'auth'.
_V15 = (
    """
    CREATE TABLE web_session (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_sha256 TEXT NOT NULL UNIQUE,
        token_name    TEXT NOT NULL,
        token_sha256  TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        last_seen_at  TEXT NOT NULL,
        expires_at    TEXT NOT NULL,
        client        TEXT,
        user_agent    TEXT
    )
    """,
    "CREATE INDEX idx_web_session_token ON web_session(token_name)",
    """
    CREATE TABLE audit_event_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        at            TEXT NOT NULL,
        kind          TEXT NOT NULL
                      CHECK (kind IN ('scan', 'refused', 'deleted', 'finding', 'config', 'auth')),
        run_id        INTEGER REFERENCES scan_run(id) ON DELETE SET NULL,
        target        TEXT NOT NULL,
        operator      TEXT,
        engagement    TEXT,
        scope_sha256  TEXT,
        detail        TEXT NOT NULL,
        prev_hash     TEXT NOT NULL UNIQUE,
        hash          TEXT NOT NULL UNIQUE
    )
    """,
    "INSERT INTO audit_event_new SELECT * FROM audit_event",
    "DROP TABLE audit_event",
    "ALTER TABLE audit_event_new RENAME TO audit_event",
    "CREATE INDEX idx_audit_run ON audit_event(run_id)",
)

_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: _V1,
    2: _V2,
    3: _V3,
    4: _V4,
    5: _V5,
    6: _V6,
    7: _V7,
    8: _V8,
    9: _V9,
    10: _V10,
    11: _V11,
    12: _V12,
    13: _V13,
    14: _V14,
    15: _V15,
}


class Storage:
    """A SQLite-backed repository for scan results."""

    def __init__(self, path: str | Path = "zues.db") -> None:
        self.path = str(path)
        # Set when opening this database upgraded an older one: where its copy is.
        self.backup_path: str | None = None
        try:
            self._conn = sqlite3.connect(self.path)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            before = self.schema_version()
            self._migrate()
            self._conn.execute("PRAGMA foreign_keys = ON")
            if 0 < before < 11 <= SCHEMA_VERSION:
                self.rebuild_inventory()  # runs stored before the inventory existed
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
                f"database {self.path} has schema v{current}, but this ZuesScan only "
                f"understands up to v{SCHEMA_VERSION}; upgrade ZuesScan"
            )
        if current == SCHEMA_VERSION:
            return
        if current > 0:
            self._backup(current)
            log.info(
                "upgrading %s from schema v%d to v%d (copy kept at %s)",
                self.path,
                current,
                SCHEMA_VERSION,
                self.backup_path,
                extra={"event": "db.migrate"},
            )

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
        """Persist a whole scan run atomically, with its audit event; return its id."""
        # IMMEDIATE: take the write lock before reading the chain's head, so that two
        # processes saving at once cannot both link to the same previous event.
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:  # COMMIT, or ROLLBACK on exception
            plan = run.plan
            cur = self._conn.execute(
                "INSERT INTO scan_run "
                "(target, status, error, started_at, finished_at, reconkit_version, "
                "profile, profile_settings, notes, plan, operator, engagement, scope_path, "
                "scope_sha256, cve_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.target,
                    str(run.status),
                    run.error,
                    run.started_at,
                    run.finished_at,
                    run.zues_version,
                    run.profile,
                    None
                    if run.profile_settings is None
                    else json.dumps(run.profile_settings, sort_keys=True),
                    json.dumps(run.notes),
                    None if plan is None else json.dumps(_plan_json(plan)),
                    run.operator,
                    run.engagement,
                    run.scope_path,
                    run.scope_sha256,
                    run.cve_source,
                ),
            )
            run_id = int(cur.lastrowid or 0)
            self._keep_scope(run.scope_sha256, run.scope_text)
            self._insert_plugins(run_id, run)
            self._conn.executemany(
                "INSERT INTO scan_run_out_of_scope (run_id, host) VALUES (?, ?)",
                [(run_id, host) for host in run.out_of_scope],
            )
            self._insert_outputs(run_id, run.raw_outputs)
            for asset in run.assets:
                cur = self._conn.execute(
                    "INSERT INTO asset (run_id, host, ip, names) VALUES (?, ?, ?, ?)",
                    (run_id, asset.host, asset.ip, json.dumps(asset.names)),
                )
                asset_id = int(cur.lastrowid or 0)
                service_ids = self._insert_services(asset_id, asset.services)
                self._insert_findings(asset_id, asset.findings, service_ids)
                self._insert_route(asset_id, asset.route)
            # The inventory moves with the run, in the same transaction (D1).
            inventory_store.apply_run(self._conn, run_id, run)
            log.info(
                "run #%d saved: %s, %d host(s), %d finding(s)",
                run_id,
                run.status,
                len(run.assets),
                sum(len(a.findings) for a in run.assets),
                extra={"event": "run.saved", "run_id": run_id},
            )
            detail: dict[str, Any] = {
                "run_id": run_id,
                "status": str(run.status),
                "started_at": run.started_at,
                "hosts": len(run.assets),
                "findings": sum(len(a.findings) for a in run.assets),
                # The evidence, tied into the chain: rewriting it breaks the chain.
                "raw_sha256": [o.sha256 for o in run.raw_outputs],
            }
            if plan is not None:
                detail["plan"] = _plan_json(plan)
            if run.error:
                detail["error"] = run.error
            self._append_audit(
                AuditEvent(
                    at=run.finished_at,
                    kind=AuditKind.SCAN,
                    target=run.target,
                    operator=run.operator,
                    engagement=run.engagement,
                    scope_sha256=run.scope_sha256,
                    detail=detail,
                ),
                run_id=run_id,
            )
        return run_id

    def record_refusal(
        self,
        target: str,
        reason: str,
        *,
        operator: str | None,
        engagement: str | None,
        scope_sha256: str | None,
        scope_text: str | None = None,
        at: str | None = None,
    ) -> None:
        """Keep a trace of a scan the scope guard refused (nothing was probed)."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            self._keep_scope(scope_sha256, scope_text)
            self._append_audit(
                AuditEvent(
                    at=at or datetime.now(UTC).isoformat(),
                    kind=AuditKind.REFUSED,
                    target=target,
                    operator=operator,
                    engagement=engagement,
                    scope_sha256=scope_sha256,
                    detail={"reason": reason},
                )
            )

    # --- the dashboard's sessions (schema 15) ----------------------------------------------

    def open_session(
        self,
        *,
        secret_sha256: str,
        token_name: str,
        token_sha256: str,
        at: str,
        expires_at: str,
        client: str | None,
        user_agent: str | None,
    ) -> int:
        """Record a session opened by signing in, with its audit event; return its id."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO web_session (secret_sha256, token_name, token_sha256, created_at, "
                "last_seen_at, expires_at, client, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (secret_sha256, token_name, token_sha256, at, at, expires_at, client, user_agent),
            )
            session_id = int(cur.lastrowid or 0)
            self._append_audit(
                _auth_event(
                    at,
                    f"token:{token_name}",
                    token_name,
                    {"action": "signed in", "session": session_id, "client": client},
                )
            )
        return session_id

    def session_by_secret(self, secret_sha256: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._conn.execute(
            "SELECT * FROM web_session WHERE secret_sha256 = ?", (secret_sha256,)
        ).fetchone()
        return row

    def sessions(self) -> list[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM web_session ORDER BY id").fetchall()

    def touch_session(self, session_id: int, at: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE web_session SET last_seen_at = ? WHERE id = ?", (at, session_id)
            )

    def close_session(self, session_id: int, *, actor: str, action: str, at: str) -> bool:
        """End a session (signed out, or ended by an admin); False if there was none."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            row = self._conn.execute(
                "SELECT token_name, client FROM web_session WHERE id = ?", (session_id,)
            ).fetchone()
            if row is None:
                return False
            self._conn.execute("DELETE FROM web_session WHERE id = ?", (session_id,))
            self._append_audit(
                _auth_event(
                    at,
                    f"token:{row['token_name']}",
                    actor,
                    {"action": action, "session": session_id, "client": row["client"]},
                )
            )
        return True

    def prune_sessions(self, *, expired_before: str, idle_before: str) -> int:
        """Forget sessions that have ended on their own (not audited: nobody acted)."""
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM web_session WHERE expires_at <= ? OR last_seen_at <= ?",
                (expired_before, idle_before),
            )
        return cur.rowcount

    def record_lockout(self, client: str, *, failures: int, seconds: int, at: str) -> None:
        """An address was locked out after too many failed sign-ins (G23)."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            self._append_audit(
                _auth_event(
                    at,
                    f"client:{client}",
                    None,
                    {"action": "locked out", "failures": failures, "seconds": seconds},
                )
            )

    # --- configuration edited in the dashboard (schema 14) ---------------------------------

    def managed_version(self) -> int:
        """Grows with every change below: a service compares it to see it must re-read."""
        row = self._conn.execute("SELECT value FROM managed_meta WHERE key = 'version'").fetchone()
        return int(row["value"]) if row else 0

    def managed_scopes(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT name, content, sha256, updated_at, updated_by FROM managed_scope ORDER BY name"
        ).fetchall()

    def managed_targets(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT name, settings, updated_at, updated_by FROM managed_target ORDER BY name"
        ).fetchall()

    def managed_tokens(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT name, sha256, role, created_at, created_by FROM managed_token ORDER BY name"
        ).fetchall()

    def save_managed_scope(self, name: str, content: str, sha256: str, actor: str) -> None:
        now = datetime.now(UTC).isoformat()
        old = self._conn.execute(
            "SELECT sha256 FROM managed_scope WHERE name = ?", (name,)
        ).fetchone()
        self._managed_change(
            "INSERT INTO managed_scope (name, content, sha256, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET content = excluded.content, "
            "sha256 = excluded.sha256, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (name, content, sha256, now, actor),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"scope:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=sha256,
                detail={
                    "action": "scope saved",
                    "previous_sha256": old["sha256"] if old else None,
                },
            ),
            snapshot=(sha256, content),
        )

    def save_managed_target(self, name: str, settings: dict[str, Any], actor: str) -> None:
        now = datetime.now(UTC).isoformat()
        exists = self._conn.execute(
            "SELECT 1 FROM managed_target WHERE name = ?", (name,)
        ).fetchone()
        self._managed_change(
            "INSERT INTO managed_target (name, settings, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET settings = excluded.settings, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (name, json.dumps(settings, sort_keys=True), now, actor),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"target:{name}",
                operator=actor,
                engagement=settings.get("engagement"),
                scope_sha256=None,
                detail={"action": "target updated" if exists else "target added", **settings},
            ),
        )

    def save_managed_token(self, name: str, sha256: str, role: str, actor: str) -> None:
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            "INSERT INTO managed_token (name, sha256, role, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, sha256, role, now, actor),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"token:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                detail={"action": "token created", "role": role},  # never the token
            ),
        )

    def delete_managed(self, kind: str, name: str, actor: str) -> bool:
        """Remove a scope, target or token; False if there was none by that name."""
        table = {"scope": "managed_scope", "target": "managed_target", "token": "managed_token"}[
            kind
        ]
        if self._conn.execute(f"SELECT 1 FROM {table} WHERE name = ?", (name,)).fetchone() is None:
            return False
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            f"DELETE FROM {table} WHERE name = ?",
            (name,),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"{kind}:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                detail={"action": f"{kind} deleted"},
            ),
        )
        return True

    def _managed_change(
        self,
        sql: str,
        params: tuple[Any, ...],
        event: AuditEvent,
        snapshot: tuple[str, str] | None = None,
    ) -> None:
        """One change, its audit event and the version bump: all or nothing."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            self._conn.execute(sql, params)
            if snapshot is not None:
                self._keep_scope(*snapshot)
            self._append_audit(event)
            self._conn.execute("UPDATE managed_meta SET value = value + 1 WHERE key = 'version'")

    def _keep_scope(self, sha256: str | None, text: str | None) -> None:
        if sha256 and text is not None:
            self._conn.execute(
                "INSERT OR IGNORE INTO scope_snapshot (sha256, content) VALUES (?, ?)",
                (sha256, text),
            )

    def _append_audit(self, event: AuditEvent, run_id: int | None = None) -> None:
        """Link `event` after the current head of the chain (inside a transaction)."""
        row = self._conn.execute("SELECT hash FROM audit_event ORDER BY id DESC LIMIT 1").fetchone()
        prev = GENESIS if row is None else row["hash"]
        self._conn.execute(
            "INSERT INTO audit_event (at, kind, run_id, target, operator, engagement, "
            "scope_sha256, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.at,
                event.kind,
                run_id,
                event.target,
                event.operator,
                event.engagement,
                event.scope_sha256,
                json.dumps(event.detail, sort_keys=True),
                prev,
                chain_hash(prev, event),
            ),
        )

    # --- inventory (D1) ------------------------------------------------------------------

    def rebuild_inventory(self) -> int:
        """Rebuild the inventory by replaying every stored run, oldest first.

        People's decisions (fixes claimed, risks accepted) are not replayed: they are
        lost, but remain in the audit trail. Returns the number of runs replayed.
        """
        ids = [r["id"] for r in self._conn.execute("SELECT id FROM scan_run ORDER BY id")]
        runs = [(run_id, self.load_run(run_id)) for run_id in ids]
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            inventory_store.clear(self._conn)
            for run_id, run in runs:
                if run is not None:
                    inventory_store.apply_run(self._conn, run_id, run)
        return len(runs)

    def inventory_findings(self, statuses: set[str] | None = None) -> list[FindingRow]:
        return inventory_store.findings(self._conn, statuses)

    def inventory_finding(self, finding_id: int) -> FindingRow | None:
        return inventory_store.finding(self._conn, finding_id)

    def inventory_hosts(self) -> list[dict[str, Any]]:
        return inventory_store.hosts(self._conn)

    def finding_history(self, finding_id: int) -> list[FindingEvent]:
        return inventory_store.events(self._conn, finding_id=finding_id)

    def changes_in_run(self, run_id: int) -> list[FindingEvent]:
        """What a run changed in the inventory: new, fixed, fake fixes, ..."""
        return inventory_store.events(self._conn, run_id=run_id)

    def finding_statuses(self) -> dict[str, str]:
        """Lifecycle status of every inventoried finding, by fingerprint."""
        return inventory_store.status_by_fingerprint(self._conn)

    def decide_finding(
        self,
        finding_id: int,
        action: str,
        *,
        actor: str,
        note: str | None = None,
        until: str | None = None,
        at: str | None = None,
    ) -> Status:
        """Record a person's decision on a finding, in the inventory and the audit trail."""
        at = at or datetime.now(UTC).isoformat()
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            old, new = inventory_store.decide(
                self._conn, finding_id, action, actor=actor, at=at, note=note, until=until
            )
            row = inventory_store.finding(self._conn, finding_id)
            assert row is not None
            detail: dict[str, Any] = {
                "finding_id": finding_id,
                "fingerprint": row.fingerprint,
                "action": action,
                "from": old,
                "to": str(new),
            }
            if note:
                detail["note"] = note
            if until:
                detail["until"] = until
            self._append_audit(
                AuditEvent(
                    at=at,
                    kind=AuditKind.FINDING,
                    target=row.ip or row.host,
                    operator=actor,
                    engagement=None,
                    scope_sha256=None,
                    detail=detail,
                )
            )
        return new

    # --- audit trail ---------------------------------------------------------------------

    def audit_events(self) -> list[tuple[int, AuditEvent, str]]:
        """Every audit event, oldest first: (id, event, hash)."""
        return [
            (row["id"], _event(row), row["hash"])
            for row in self._conn.execute("SELECT * FROM audit_event ORDER BY id")
        ]

    def scope_snapshot(self, sha256: str) -> str | None:
        """The scope file content recorded under `sha256` (a prefix is enough)."""
        rows = self._conn.execute(
            "SELECT content FROM scope_snapshot WHERE sha256 LIKE ? || '%' LIMIT 2",
            (sha256.lower(),),
        ).fetchall()
        return rows[0]["content"] if len(rows) == 1 else None

    def verify_audit(self) -> ChainReport:
        """Recompute the chain, and check each scan's evidence against it."""
        problems: list[str] = []
        prev = GENESIS
        rows = self._conn.execute("SELECT * FROM audit_event ORDER BY id").fetchall()
        for row in rows:
            event = _event(row)
            if row["prev_hash"] != prev:
                problems.append(
                    f"event #{row['id']}: does not follow the event before it "
                    "(an event was removed or reordered)"
                )
            expected = chain_hash(row["prev_hash"], event)
            if row["hash"] != expected:
                problems.append(f"event #{row['id']}: its content was changed after it was written")
            prev = row["hash"]
            if event.kind == AuditKind.SCAN:
                problems.extend(self._check_evidence(row["id"], event))
        return ChainReport(events=len(rows), head=prev, problems=problems)

    def _check_evidence(self, event_id: int, event: AuditEvent) -> list[str]:
        run_id = event.detail.get("run_id")
        if run_id is None:
            return []
        exists = self._conn.execute("SELECT 1 FROM scan_run WHERE id = ?", (run_id,)).fetchone()
        if exists is None:
            deleted = any(
                json.loads(r["detail"]).get("run_id") == run_id
                for r in self._conn.execute(
                    "SELECT detail FROM audit_event WHERE kind = 'deleted'"
                ).fetchall()
            )
            if deleted:
                return []
            return [f"event #{event_id}: run #{run_id} is gone, with no record of its deletion"]
        stored = [
            row["sha256"]
            for row in self._conn.execute(
                "SELECT sha256 FROM scan_run_output WHERE run_id = ? ORDER BY id", (run_id,)
            )
        ]
        if stored != event.detail.get("raw_sha256", []):
            return [f"event #{event_id}: the raw output of run #{run_id} is not what was recorded"]
        try:
            self.outputs_for_run(run_id)  # each output still matches its own hash
        except StorageError as exc:
            return [f"event #{event_id}: {exc}"]
        return []

    def _insert_route(self, asset_id: int, route: list[Hop]) -> None:
        self._conn.executemany(
            "INSERT INTO route_hop (asset_id, ttl, ip, rtt_ms, name) VALUES (?, ?, ?, ?, ?)",
            [(asset_id, h.ttl, h.ip, h.rtt_ms, h.name) for h in route],
        )

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
                "(asset_id, port, protocol, state, name, product, version, cpe, banner, web) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    json.dumps(s.web.to_dict()) if s.web else None,
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
                    f.rule_id,
                    f.description,
                    f.evidence,
                    fp,
                    None if f.confidence is None else str(f.confidence),
                    f.cvss_score,
                    f.cvss_vector,
                    ",".join(f.cwe),
                    f.kev_added,
                    f.epss,
                )
            )
        self._conn.executemany(
            "INSERT INTO finding "
            "(asset_id, service_id, title, severity, cve, rule_id, description, evidence, "
            "fingerprint, confidence, cvss_score, cvss_vector, cwe, kev_added, epss) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def _insert_outputs(self, run_id: int, outputs: list[RawOutput]) -> None:
        self._conn.executemany(
            "INSERT INTO scan_run_output "
            "(run_id, plugin, format, command, stderr, size, sha256, content) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    o.plugin,
                    o.format,
                    json.dumps(list(o.command)),
                    o.stderr,
                    o.size,
                    o.sha256,
                    zlib.compress(o.content.encode("utf-8")),
                )
                for o in outputs
            ],
        )

    def delete_run(self, run_id: int, operator: str | None = None) -> bool:
        """Delete a run and everything recorded for it; False if there is no such run.

        The deletion itself is recorded in the audit trail: data may go, its history
        may not.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            row = self._conn.execute(
                "SELECT target, status, engagement, scope_sha256 FROM scan_run WHERE id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                return False
            self._conn.execute("DELETE FROM scan_run WHERE id = ?", (run_id,))
            self._append_audit(
                AuditEvent(
                    at=datetime.now(UTC).isoformat(),
                    kind=AuditKind.DELETED,
                    target=row["target"],
                    operator=operator,
                    engagement=row["engagement"],
                    scope_sha256=row["scope_sha256"],
                    detail={"run_id": run_id, "status": row["status"]},
                )
            )
        return True

    # --- reading -----------------------------------------------------------------------

    def load_run(self, run_id: int) -> ScanRun | None:
        """Read a whole run back, as it was saved; None if there is no such run.

        `plan` (what the scope guard authorised) is not stored yet, so it comes back
        as None — see G21.
        """
        row = self._conn.execute(
            "SELECT target, status, error, started_at, finished_at, reconkit_version, "
            "profile, profile_settings, notes, plan, operator, engagement, scope_path, "
            "scope_sha256, cve_source FROM scan_run WHERE id = ?",
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
            # The column keeps the name it had before the project became ZuesScan: renaming
            # it would take a migration for no gain, and databases stay readable both ways.
            zues_version=row["reconkit_version"],
            profile=row["profile"],
            profile_settings=(
                None if row["profile_settings"] is None else json.loads(row["profile_settings"])
            ),
            notes=list(json.loads(row["notes"] or "[]")),
            plan=None if row["plan"] is None else _plan_from_json(json.loads(row["plan"])),
            operator=row["operator"],
            engagement=row["engagement"],
            scope_path=row["scope_path"],
            scope_sha256=row["scope_sha256"],
            cve_source=row["cve_source"],
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

        run.raw_outputs = self.outputs_for_run(run_id)

        services_by_id: dict[int, Service] = {}
        for a in self._conn.execute(
            "SELECT id, host, ip, names FROM asset WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall():
            asset = Asset(host=a["host"], ip=a["ip"], names=list(json.loads(a["names"] or "[]")))
            for s in self._conn.execute(
                "SELECT id, port, protocol, state, name, product, version, cpe, banner, web "
                "FROM service WHERE asset_id = ? ORDER BY id",
                (a["id"],),
            ):
                service = _service(s)
                services_by_id[s["id"]] = service
                asset.services.append(service)
            for f in self._conn.execute(
                "SELECT service_id, title, severity, cve, rule_id, description, evidence, "
                "fingerprint, confidence, cvss_score, cvss_vector, cwe, kev_added, epss "
                "FROM finding WHERE asset_id = ? ORDER BY id",
                (a["id"],),
            ):
                asset.findings.append(_finding(f, asset, services_by_id.get(f["service_id"])))
            asset.route = [
                Hop(ttl=h["ttl"], ip=h["ip"], rtt_ms=h["rtt_ms"], name=h["name"])
                for h in self._conn.execute(
                    "SELECT ttl, ip, rtt_ms, name FROM route_hop WHERE asset_id = ? ORDER BY ttl",
                    (a["id"],),
                )
            ]
            run.assets.append(asset)
        return run

    def list_runs(self, limit: int | None = None) -> list[RunSummary]:
        """The stored runs, newest first, with how much each one found."""
        rows = self._conn.execute(
            "SELECT r.id, r.target, r.status, r.started_at, r.finished_at, "
            "  (SELECT COUNT(*) FROM asset a WHERE a.run_id = r.id) AS hosts, "
            "  (SELECT COUNT(*) FROM service s JOIN asset a ON a.id = s.asset_id "
            "   WHERE a.run_id = r.id) AS services, "
            "  (SELECT COUNT(*) FROM finding f JOIN asset a ON a.id = f.asset_id "
            "   WHERE a.run_id = r.id) AS findings "
            "FROM scan_run r ORDER BY r.id DESC LIMIT ?",
            (-1 if limit is None else limit,),
        ).fetchall()
        return [
            RunSummary(
                id=r["id"],
                target=r["target"],
                status=RunStatus(r["status"]),
                started_at=r["started_at"],
                finished_at=r["finished_at"],
                hosts=r["hosts"],
                services=r["services"],
                findings=r["findings"],
            )
            for r in rows
        ]

    def latest_starts(self) -> dict[tuple[str, str | None], str]:
        """When each (target, profile) was last scanned: the newest run's start time.

        Failed runs count: the scan was attempted, and a target that fails every time
        must not be retried at every scheduler round.
        """
        rows = self._conn.execute(
            "SELECT target, profile, MAX(started_at) AS started_at FROM scan_run "
            "GROUP BY target, profile"
        ).fetchall()
        return {(r["target"], r["profile"]): r["started_at"] for r in rows}

    def latest_run_id(self) -> int | None:
        """The id of the most recent run, or None if there is none."""
        row = self._conn.execute("SELECT MAX(id) AS id FROM scan_run").fetchone()
        return None if row["id"] is None else int(row["id"])

    def outputs_for_run(self, run_id: int) -> list[RawOutput]:
        """The raw scanner output kept for a run, checked against its stored hash."""
        outputs = []
        for row in self._conn.execute(
            "SELECT id, plugin, format, command, stderr, sha256, content "
            "FROM scan_run_output WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall():
            try:
                content = zlib.decompress(row["content"]).decode("utf-8")
            except (zlib.error, UnicodeDecodeError) as exc:
                raise StorageError(
                    f"raw output #{row['id']} of run {run_id} is unreadable: {exc}"
                ) from exc
            output = RawOutput(
                plugin=row["plugin"],
                format=row["format"],
                command=tuple(json.loads(row["command"])),
                content=content,
                stderr=row["stderr"],
            )
            if output.sha256 != row["sha256"]:
                # Evidence that no longer matches its hash is not evidence.
                raise StorageError(
                    f"raw output #{row['id']} of run {run_id} does not match its "
                    "stored SHA-256: the database was altered or is damaged"
                )
            outputs.append(output)
        return outputs

    def services_for_run(self, run_id: int) -> list[Service]:
        """The services recorded for a run, across all its hosts, by port."""
        rows = self._conn.execute(
            "SELECT s.port, s.protocol, s.state, s.name, s.product, s.version, s.cpe, s.banner, "
            "s.web FROM service s JOIN asset a ON a.id = s.asset_id "
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
        web=WebPage.from_dict(json.loads(row["web"])) if row["web"] else None,
    )


def _finding(row: sqlite3.Row, asset: Asset, service: Service | None) -> Finding:
    return Finding(
        asset=asset.host,
        ip=asset.ip,
        rule_id=row["rule_id"],
        title=row["title"],
        severity=Severity(row["severity"]),
        service=service,
        cve=row["cve"],
        description=row["description"] or "",
        evidence=row["evidence"] or "",
        fingerprint=row["fingerprint"],
        confidence=None if row["confidence"] is None else Confidence(row["confidence"]),
        cvss_score=row["cvss_score"],
        cvss_vector=row["cvss_vector"],
        cwe=tuple(c for c in (row["cwe"] or "").split(",") if c),
        kev_added=row["kev_added"],
        epss=row["epss"],
    )


def _plan_json(plan: ScanTarget) -> dict[str, Any]:
    return {
        "requested": plan.requested,
        "addresses": list(plan.addresses),
        "exclude": list(plan.exclude),
        "hostname": plan.hostname,
    }


def _plan_from_json(data: dict[str, Any]) -> ScanTarget:
    return ScanTarget(
        requested=data["requested"],
        addresses=tuple(data["addresses"]),
        exclude=tuple(data.get("exclude", [])),
        hostname=data.get("hostname"),
    )


def _event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        at=row["at"],
        kind=row["kind"],
        target=row["target"],
        operator=row["operator"],
        engagement=row["engagement"],
        scope_sha256=row["scope_sha256"],
        detail=json.loads(row["detail"]),
    )


def _auth_event(at: str, target: str, operator: str | None, detail: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        at=at,
        kind=AuditKind.AUTH,
        target=target,
        operator=operator,
        engagement=None,
        scope_sha256=None,
        detail=detail,
    )
