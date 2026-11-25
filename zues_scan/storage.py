"""SQLite persistence via a thin repository.

One `scan_run` (with all its assets, services and findings) is written inside a single
transaction, so a crash mid-write rolls back cleanly rather than leaving half a scan
in the database (GHI-CHU.md section 6). The repository hides SQL behind methods, so
swapping SQLite for PostgreSQL later is a storage-layer change only.

The schema is versioned. Opening a database brings it up to `SCHEMA_VERSION` by
applying, in order, the migrations it has not seen yet; the `schema_version` table
records each one. A fresh database simply starts at version 0 and takes the same path,
so there is one way to build the schema and every migration is exercised by every test.

The database uses write-ahead logging (WAL): the web (reading, recording sessions) and the
workers (saving runs) do not wait for one another — a long read no longer holds a run's
save back, and a save no longer blocks readers. The mode is kept in the file; it is set
when a database is created or migrated, and by the services when they start
(`prefer_wal`: e.g. after a backup was restored), never by merely opening a database —
a backup stays byte for byte what its recorded SHA-256 says. WAL needs a local disk
(shared memory next to the file): on a network share SQLite stays in its default mode,
which is logged. Writers still take turns; a busy database is waited on for up to
`BUSY_SECONDS`.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from zues_scan import inventory_store
from zues_scan.alerts import Alert, AlertPolicy, RunFacts
from zues_scan.audit import GENESIS, AuditEvent, AuditKind, ChainReport, chain_hash
from zues_scan.inventory import Status, host_key
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
SCHEMA_VERSION = 22

# How long a writer waits for another to finish before "database is locked".
BUSY_SECONDS = 15.0


class StorageError(Exception):
    """The database cannot be used: unreadable, inconsistent, or from a newer ZuesScan."""


class ProposalError(Exception):
    """A scope proposal cannot be decided: not pending, or its scope changed since."""


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
    target_name: str | None = None  # the service's configured target, if any


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

# Version 16: the alerts' outbox (G23). An alert is queued here — a scan's in the same
# transaction as its run — and delivered afterwards with retries: `attempts`, when to try
# next, the last error; `sent_at` or `gave_up_at` once it is over. `dedupe_key` keeps a
# lasting condition from alerting at every scan.
_V16 = (
    """
    CREATE TABLE alert_outbox (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at   TEXT NOT NULL,
        kind         TEXT NOT NULL,
        dedupe_key   TEXT,
        payload      TEXT NOT NULL,
        run_id       INTEGER REFERENCES scan_run(id) ON DELETE SET NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        next_try_at  TEXT NOT NULL,
        last_error   TEXT,
        sent_at      TEXT,
        gave_up_at   TEXT
    )
    """,
    "CREATE INDEX idx_alert_due ON alert_outbox(next_try_at) "
    "WHERE sent_at IS NULL AND gave_up_at IS NULL",
    "CREATE INDEX idx_alert_dedupe ON alert_outbox(dedupe_key, created_at)",
    "CREATE INDEX idx_alert_run ON alert_outbox(run_id)",
)

# Version 17: dashboard tokens expire (G30): `expires_at` (NULL: never), and are rotated —
# a new value under the same name, the old one (and its sessions) over at once.
_V17 = (
    "ALTER TABLE managed_token ADD COLUMN expires_at TEXT",
    "ALTER TABLE managed_token ADD COLUMN rotated_at TEXT",
)

# Version 18: two people for a scope change (G30). With approval on, a scope saved or
# deleted in the dashboard is a *proposal* until another admin approves it; `base_sha256` is
# the scope it was made against (a proposal whose scope changed since is not approved).
# `managed_token.rotated_by`: who last saw a token's value, to tell who may approve.
_V18 = (
    """
    CREATE TABLE scope_proposal (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        action        TEXT NOT NULL CHECK (action IN ('save', 'delete')),
        content       TEXT,
        sha256        TEXT,
        base_sha256   TEXT,
        reason        TEXT,
        proposed_by   TEXT NOT NULL,
        proposed_at   TEXT NOT NULL,
        status        TEXT NOT NULL CHECK (status IN
                      ('pending', 'approved', 'rejected', 'withdrawn', 'superseded')),
        decided_by    TEXT,
        decided_at    TEXT,
        decision_note TEXT
    )
    """,
    "CREATE INDEX idx_scope_proposal_status ON scope_proposal(status, name)",
    "ALTER TABLE managed_token ADD COLUMN rotated_by TEXT",
)

# Version 19: per-target permissions (G23). Each run records the configured target it
# scanned (`target_name`: NULL for CLI scans and runs from before, until the service matches
# them), and a dashboard token may be limited to targets (`targets`: a JSON list of name
# patterns; NULL: every target).
_V19 = (
    "ALTER TABLE scan_run ADD COLUMN target_name TEXT",
    "CREATE INDEX idx_scan_run_target_name ON scan_run(target_name)",
    "ALTER TABLE managed_token ADD COLUMN targets TEXT",
)

# Version 20: a dashboard token may be held to a number of scan requests an hour (G26).
_V20 = ("ALTER TABLE managed_token ADD COLUMN scans_per_hour INTEGER",)

# Version 21: what a web check saw under each name of the host (virtual hosts, G29):
# a JSON list of pages like `web`'s (NULL: none asked by name).
_V21 = ("ALTER TABLE service ADD COLUMN vhosts TEXT",)

# Version 22: a test for a finding's CVE that ran and did not match (G24), on the run's
# finding and, latest known, on the inventory's.
_V22 = (
    "ALTER TABLE finding ADD COLUMN tried TEXT",
    "ALTER TABLE inv_finding ADD COLUMN tried TEXT",
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
    16: _V16,
    17: _V17,
    18: _V18,
    19: _V19,
    20: _V20,
    21: _V21,
    22: _V22,
}


class Storage:
    """A SQLite-backed repository for scan results."""

    def __init__(self, path: str | Path = "zues.db") -> None:
        self.path = str(path)
        # Set when opening this database upgraded an older one: where its copy is.
        self.backup_path: str | None = None
        # Set by the service when it has a webhook: each change of a scope, target or token
        # queues a `config_changed` alert with its audit event (G30).
        self.config_alerts = False
        try:
            self._conn = sqlite3.connect(self.path, timeout=BUSY_SECONDS)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            before = self.schema_version()
            if self._migrate():
                self.use_wal()  # written anyway: created or upgraded
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

    def _migrate(self) -> bool:
        """Bring the database up to `SCHEMA_VERSION`, all or nothing; True if it changed."""
        current = self.schema_version()
        if current > SCHEMA_VERSION:
            # Never touch data written by a newer version: we could corrupt it.
            raise StorageError(
                f"database {self.path} has schema v{current}, but this ZuesScan only "
                f"understands up to v{SCHEMA_VERSION}; upgrade ZuesScan"
            )
        if current == SCHEMA_VERSION:
            return False
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
        return True

    def use_wal(self) -> str:
        """Switch the database to write-ahead logging (kept in the file); the mode now."""
        if self.path == ":memory:":
            return self.journal_mode()
        mode = str(self._conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
        if mode != "wal":
            log.warning(
                "%s cannot use write-ahead logging (journal mode stays %s): readers and "
                "writers will wait for each other; keep the database on a local disk",
                self.path,
                mode,
            )
        return mode

    def journal_mode(self) -> str:
        return str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def _backup(self, version: int) -> None:
        """Copy the database aside before changing its schema."""
        if self.path == ":memory:":
            return
        backup_path = f"{self.path}.v{version}.bak"
        target = sqlite3.connect(backup_path)
        try:
            self._conn.backup(target)  # a consistent snapshot, unlike copying the file
            target.execute("PRAGMA journal_mode = DELETE")  # one self-contained file
        finally:
            target.close()
        self.backup_path = backup_path

    # --- writing -----------------------------------------------------------------------

    def save_run(self, run: ScanRun, alerts: AlertPolicy | None = None) -> int:
        """Persist a whole scan run atomically, with its audit event; return its id.

        With `alerts`, the alerts it decides on are queued in the same transaction: saved
        together with the run, or not at all (the outbox, G23).
        """
        # IMMEDIATE: take the write lock before reading the chain's head, so that two
        # processes saving at once cannot both link to the same previous event.
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:  # COMMIT, or ROLLBACK on exception
            plan = run.plan
            cur = self._conn.execute(
                "INSERT INTO scan_run "
                "(target, status, error, started_at, finished_at, reconkit_version, "
                "profile, profile_settings, notes, plan, operator, engagement, scope_path, "
                "scope_sha256, cve_source, target_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    run.target_name,
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
            if alerts is not None:
                self._queue_run_alerts(alerts, run, run_id)
        return run_id

    def _queue_run_alerts(self, alerts: AlertPolicy, run: ScanRun, run_id: int) -> None:
        facts = RunFacts(
            run=run,
            run_id=run_id,
            changes=inventory_store.events(self._conn, run_id=run_id),
            failed_before=self._failed_before(run, run_id),
        )
        try:
            decided = alerts(facts)
            for alert in decided:
                json.dumps(alert.payload)  # fails here, not halfway through the inserts
        except Exception:  # noqa: BLE001 - a broken alert must never lose the run
            log.exception("deciding the alerts of run #%d failed; the run is saved", run_id)
            return
        for alert in decided:
            self._queue_alert(alert, run.finished_at, run_id)

    def _failed_before(self, run: ScanRun, run_id: int) -> int:
        """Failed runs of the same target and profile in a row, just before `run_id`."""
        count = 0
        for row in self._conn.execute(
            "SELECT status FROM scan_run WHERE target = ? AND profile IS ? AND id < ? "
            "ORDER BY id DESC LIMIT 100",
            (run.target, run.profile, run_id),
        ):
            if row["status"] != str(RunStatus.FAILED):
                break
            count += 1
        return count

    # --- alerts' outbox (schema 16) -------------------------------------------------------

    def queue_alert(self, alert: Alert, at: str, run_id: int | None = None) -> int | None:
        """Queue an alert for delivery; its id, or None if `dedupe_key` held it back."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            return self._queue_alert(alert, at, run_id)

    def _queue_alert(self, alert: Alert, at: str, run_id: int | None) -> int | None:
        # One format in this table (UTC, to the second), so that text order is time order.
        moment = datetime.fromisoformat(at).astimezone(UTC)
        at = moment.isoformat(timespec="seconds")
        if alert.dedupe_key is not None and alert.dedupe_seconds > 0:
            since = moment - timedelta(seconds=alert.dedupe_seconds)
            recent = self._conn.execute(
                "SELECT 1 FROM alert_outbox WHERE dedupe_key = ? AND created_at > ? LIMIT 1",
                (alert.dedupe_key, since.isoformat(timespec="seconds")),
            ).fetchone()
            if recent is not None:
                log.info("alert %s held back: the same was queued recently", alert.dedupe_key)
                return None
        cur = self._conn.execute(
            "INSERT INTO alert_outbox (created_at, kind, dedupe_key, payload, run_id, "
            "next_try_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                at,
                alert.kind,
                alert.dedupe_key,
                json.dumps(alert.payload, ensure_ascii=False, sort_keys=True),
                run_id,
                at,
            ),
        )
        return int(cur.lastrowid or 0)

    def claim_alerts(
        self, *, at: str, lease_until: str, limit: int, ids: list[int] | None = None
    ) -> list[sqlite3.Row]:
        """Take the alerts due at `at` for delivery (at most `limit`): each one's next try
        moves to `lease_until`, so that another process does not send it meanwhile."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            sql = (
                "SELECT * FROM alert_outbox WHERE sent_at IS NULL AND gave_up_at IS NULL "
                "AND next_try_at <= ?"
            )
            params: list[Any] = [at]
            if ids is not None:
                sql += f" AND id IN ({', '.join('?' for _ in ids)})"
                params.extend(ids)
            rows = self._conn.execute(f"{sql} ORDER BY id LIMIT ?", (*params, limit)).fetchall()
            self._conn.executemany(
                "UPDATE alert_outbox SET attempts = attempts + 1, next_try_at = ? WHERE id = ?",
                [(lease_until, r["id"]) for r in rows],
            )
        return rows

    def alert_sent(self, alert_id: int, at: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE alert_outbox SET sent_at = ?, last_error = NULL WHERE id = ?",
                (at, alert_id),
            )

    def alert_failed(self, alert_id: int, error: str, *, retry_at: str | None, at: str) -> None:
        """A delivery failed: try again at `retry_at`, or give up (None)."""
        with self._conn:
            if retry_at is None:
                self._conn.execute(
                    "UPDATE alert_outbox SET last_error = ?, gave_up_at = ? WHERE id = ?",
                    (error[:500], at, alert_id),
                )
            else:
                self._conn.execute(
                    "UPDATE alert_outbox SET last_error = ?, next_try_at = ? WHERE id = ?",
                    (error[:500], retry_at, alert_id),
                )

    def retry_alert(self, alert_id: int, at: str) -> bool:
        """Make an alert that was not delivered due now (again); False if none / sent."""
        with self._conn:
            cur = self._conn.execute(
                "UPDATE alert_outbox SET gave_up_at = NULL, next_try_at = ? "
                "WHERE id = ? AND sent_at IS NULL",
                (at, alert_id),
            )
        return cur.rowcount == 1

    def prune_alerts(self, before: str) -> int:
        """Delete the alerts over by `before` (sent or given up then) and those never
        delivered that were raised by then; the number deleted. Not audited: the audit
        trail records what people did, the outbox only what was sent about it."""
        moment = datetime.fromisoformat(before).astimezone(UTC).isoformat(timespec="seconds")
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM alert_outbox WHERE COALESCE(sent_at, gave_up_at, created_at) <= ?",
                (moment,),
            )
        return cur.rowcount

    def alert_rows(self, limit: int = 50, ids: list[int] | None = None) -> list[sqlite3.Row]:
        """The newest alerts (or those with `ids`), whatever their state."""
        if ids is not None:
            marks = ", ".join("?" for _ in ids)
            return self._conn.execute(
                f"SELECT * FROM alert_outbox WHERE id IN ({marks}) ORDER BY id DESC", ids
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM alert_outbox ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

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

    def record_lockout(
        self, client: str, *, failures: int, seconds: int, at: str, alert: Alert | None = None
    ) -> None:
        """An address was locked out after too many failed sign-ins (G23); with `alert`,
        queued with the audit event."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            if alert is not None:
                self._queue_alert(alert, at, None)
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
            "SELECT name, sha256, role, created_at, created_by, expires_at, rotated_at, "
            "rotated_by, targets, scans_per_hour FROM managed_token ORDER BY name"
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

    def save_managed_token(
        self,
        name: str,
        sha256: str,
        role: str,
        actor: str,
        expires_at: str | None = None,
        targets: list[str] | None = None,
        scans_per_hour: int | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            "INSERT INTO managed_token (name, sha256, role, created_at, created_by, expires_at, "
            "targets, scans_per_hour) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                sha256,
                role,
                now,
                actor,
                expires_at,
                None if targets is None else json.dumps(targets),
                scans_per_hour,
            ),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"token:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                # Never the token, nor its hash.
                detail={
                    "action": "token created",
                    "role": role,
                    "expires_at": expires_at,
                    "targets": targets,
                    "scans_per_hour": scans_per_hour,
                },
            ),
        )

    def set_managed_token_quota(self, name: str, scans_per_hour: int | None, actor: str) -> None:
        """How many scans a dashboard token may request an hour (None: no limit)."""
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            "UPDATE managed_token SET scans_per_hour = ? WHERE name = ?",
            (scans_per_hour, name),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"token:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                detail={"action": "token scan limit changed", "scans_per_hour": scans_per_hour},
            ),
        )

    def set_managed_token_targets(self, name: str, targets: list[str] | None, actor: str) -> None:
        """Which targets a dashboard token may see and act on (None: every one)."""
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            "UPDATE managed_token SET targets = ? WHERE name = ?",
            (None if targets is None else json.dumps(targets), name),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"token:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                detail={"action": "token targets changed", "targets": targets},
            ),
        )

    def rotate_managed_token(
        self, name: str, sha256: str, actor: str, expires_at: str | None
    ) -> None:
        """A new value for a dashboard token: the old one stops working at once."""
        now = datetime.now(UTC).isoformat()
        self._managed_change(
            "UPDATE managed_token SET sha256 = ?, expires_at = ?, rotated_at = ?, rotated_by = ? "
            "WHERE name = ?",
            (sha256, expires_at, now, actor, name),
            AuditEvent(
                at=now,
                kind=AuditKind.CONFIG,
                target=f"token:{name}",
                operator=actor,
                engagement=None,
                scope_sha256=None,
                detail={"action": "token rotated", "expires_at": expires_at},
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
        """One change, its audit event, its alert and the version bump: all or nothing."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            self._conn.execute(sql, params)
            if snapshot is not None:
                self._keep_scope(*snapshot)
            self._append_audit(event)
            self._conn.execute("UPDATE managed_meta SET value = value + 1 WHERE key = 'version'")
            if self.config_alerts:
                self._queue_alert(_config_alert(event), event.at, None)

    # --- scope proposals (schema 18) --------------------------------------------------------

    def propose_scope(
        self,
        name: str,
        *,
        action: str,
        content: str | None,
        sha256: str | None,
        reason: str | None,
        actor: str,
        at: str,
    ) -> int:
        """Record a proposed scope change (save or delete) against the scope as it is now; a
        pending proposal for the same scope is superseded. Audited, nothing applied."""
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            base = self._conn.execute(
                "SELECT sha256 FROM managed_scope WHERE name = ?", (name,)
            ).fetchone()
            cur = self._conn.execute(
                "INSERT INTO scope_proposal (name, action, content, sha256, base_sha256, reason, "
                "proposed_by, proposed_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (
                    name,
                    action,
                    content,
                    sha256,
                    base["sha256"] if base else None,
                    reason,
                    actor,
                    at,
                ),
            )
            proposal = int(cur.lastrowid or 0)
            self._conn.execute(
                "UPDATE scope_proposal SET status = 'superseded', decided_by = ?, decided_at = ?, "
                "decision_note = ? WHERE name = ? AND status = 'pending' AND id != ?",
                (actor, at, f"replaced by proposal #{proposal}", name, proposal),
            )
            self._config_event(
                at,
                name,
                actor,
                {
                    "action": f"scope {'deletion' if action == 'delete' else 'change'} proposed",
                    "proposal": proposal,
                    "reason": reason,
                },
                sha256,
            )
        return proposal

    def scope_proposals(self, statuses: tuple[str, ...] | None = None) -> list[sqlite3.Row]:
        if statuses is None:
            return self._conn.execute("SELECT * FROM scope_proposal ORDER BY id DESC").fetchall()
        marks = ", ".join("?" for _ in statuses)
        return self._conn.execute(
            f"SELECT * FROM scope_proposal WHERE status IN ({marks}) ORDER BY id DESC", statuses
        ).fetchall()

    def scope_proposal(self, proposal_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._conn.execute(
            "SELECT * FROM scope_proposal WHERE id = ?", (proposal_id,)
        ).fetchone()
        return row

    def decide_scope_proposal(
        self, proposal_id: int, *, decision: str, actor: str, note: str | None, at: str
    ) -> sqlite3.Row:
        """Approve (the change is applied, in the same transaction), reject or withdraw a
        pending proposal. Who may do which is the caller's rule (managed.decide_proposal);
        this keeps it consistent: still pending, and the scope still what it was proposed
        against. Returns the proposal as decided."""
        status = {"approve": "approved", "reject": "rejected", "withdraw": "withdrawn"}[decision]
        self._conn.execute("BEGIN IMMEDIATE")
        with self._conn:
            row = self.scope_proposal(proposal_id)
            if row is None or row["status"] != "pending":
                raise ProposalError(
                    f"proposal #{proposal_id} is {row['status'] if row else 'unknown'}, not pending"
                )
            name = row["name"]
            if decision == "approve":
                current = self._conn.execute(
                    "SELECT sha256, content FROM managed_scope WHERE name = ?", (name,)
                ).fetchone()
                if (current["sha256"] if current else None) != row["base_sha256"]:
                    self._conn.execute(
                        "UPDATE scope_proposal SET status = 'superseded', decided_by = ?, "
                        "decided_at = ?, decision_note = ? WHERE id = ?",
                        (actor, at, "the scope changed since it was proposed", proposal_id),
                    )
                    self._conn.commit()
                    raise ProposalError(
                        f"scope {name} changed since proposal #{proposal_id} was made: "
                        "propose the change again against the scope as it is now"
                    )
                self._apply_proposal(row, actor, at, current)
            self._conn.execute(
                "UPDATE scope_proposal SET status = ?, decided_by = ?, decided_at = ?, "
                "decision_note = ? WHERE id = ?",
                (status, actor, at, note, proposal_id),
            )
            if decision != "approve":
                change = "deletion" if row["action"] == "delete" else "change"
                self._config_event(
                    at,
                    name,
                    actor,
                    {
                        "action": f"scope {change} {status}",
                        "proposal": proposal_id,
                        "proposed_by": row["proposed_by"],
                        "note": note,
                    },
                    row["sha256"],
                )
        decided = self.scope_proposal(proposal_id)
        assert decided is not None
        return decided

    def _apply_proposal(
        self, row: sqlite3.Row, actor: str, at: str, current: sqlite3.Row | None
    ) -> None:
        name = row["name"]
        detail = {"proposal": row["id"], "proposed_by": row["proposed_by"], "approved_by": actor}
        if row["action"] == "delete":
            self._conn.execute("DELETE FROM managed_scope WHERE name = ?", (name,))
            self._config_event(at, name, actor, {"action": "scope deleted", **detail}, None)
        else:
            self._conn.execute(
                "INSERT INTO managed_scope (name, content, sha256, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                "content = excluded.content, sha256 = excluded.sha256, "
                "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                (name, row["content"], row["sha256"], at, row["proposed_by"]),
            )
            self._keep_scope(row["sha256"], row["content"])
            previous = current["sha256"] if current else None
            self._config_event(
                at,
                name,
                actor,
                {"action": "scope saved", "previous_sha256": previous, **detail},
                row["sha256"],
            )
        self._conn.execute("UPDATE managed_meta SET value = value + 1 WHERE key = 'version'")

    def _config_event(
        self, at: str, scope: str, actor: str, detail: dict[str, Any], sha256: str | None
    ) -> None:
        """A scope's config audit event (and its alert), inside the caller's transaction."""
        event = AuditEvent(
            at=at,
            kind=AuditKind.CONFIG,
            target=f"scope:{scope}",
            operator=actor,
            engagement=None,
            scope_sha256=sha256,
            detail={k: v for k, v in detail.items() if v is not None},
        )
        self._append_audit(event)
        if self.config_alerts:
            self._queue_alert(_config_alert(event), at, None)

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
                "(asset_id, port, protocol, state, name, product, version, cpe, banner, web, "
                "vhosts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    json.dumps([p.to_dict() for p in s.vhosts]) if s.vhosts else None,
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
                    f.tried,
                )
            )
        self._conn.executemany(
            "INSERT INTO finding "
            "(asset_id, service_id, title, severity, cve, rule_id, description, evidence, "
            "fingerprint, confidence, cvss_score, cvss_vector, cwe, kev_added, epss, tried) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            "scope_sha256, cve_source, target_name FROM scan_run WHERE id = ?",
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
            target_name=row["target_name"],
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
                "SELECT id, port, protocol, state, name, product, version, cpe, banner, web, "
                "vhosts FROM service WHERE asset_id = ? ORDER BY id",
                (a["id"],),
            ):
                service = _service(s)
                services_by_id[s["id"]] = service
                asset.services.append(service)
            for f in self._conn.execute(
                "SELECT service_id, title, severity, cve, rule_id, description, evidence, "
                "fingerprint, confidence, cvss_score, cvss_vector, cwe, kev_added, epss, tried "
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

    def list_runs(
        self,
        limit: int | None = None,
        before: int | None = None,
        targets: tuple[str, ...] | None = None,
    ) -> list[RunSummary]:
        """The stored runs, newest first, with how much each one found; with `before`, only
        those older than run #before (the next page: ids never move, unlike an offset); with
        `targets` (name patterns), only runs of those configured targets."""
        where, params = _targets_clause(targets, "r.target_name")
        rows = self._conn.execute(
            "SELECT r.id, r.target, r.status, r.started_at, r.finished_at, r.target_name, "
            "  (SELECT COUNT(*) FROM asset a WHERE a.run_id = r.id) AS hosts, "
            "  (SELECT COUNT(*) FROM service s JOIN asset a ON a.id = s.asset_id "
            "   WHERE a.run_id = r.id) AS services, "
            "  (SELECT COUNT(*) FROM finding f JOIN asset a ON a.id = f.asset_id "
            "   WHERE a.run_id = r.id) AS findings "
            f"FROM scan_run r WHERE r.id < ?{where} ORDER BY r.id DESC LIMIT ?",
            (
                2**63 - 1 if before is None else before,
                *params,
                -1 if limit is None else limit,
            ),
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
                target_name=r["target_name"],
            )
            for r in rows
        ]

    def run_target_name(self, run_id: int) -> tuple[bool, str | None]:
        """(whether run #run_id exists, the configured target it scanned)."""
        row = self._conn.execute(
            "SELECT target_name FROM scan_run WHERE id = ?", (run_id,)
        ).fetchone()
        return (row is not None, row["target_name"] if row else None)

    def host_keys_seen_by(self, targets: tuple[str, ...]) -> set[str]:
        """The hosts (inventory keys) that runs of these targets (name patterns) found."""
        where, params = _targets_clause(targets, "r.target_name")
        rows = self._conn.execute(
            "SELECT DISTINCT a.host, a.ip FROM asset a JOIN scan_run r ON r.id = a.run_id "
            f"WHERE 1 = 1{where}",
            params,
        ).fetchall()
        return {host_key(r["ip"], r["host"]) for r in rows}

    def name_runs(self, names: dict[tuple[str, str | None], str]) -> int:
        """Give runs without a target name the one configured target that scans the same
        address with the same profile (`names`: (address, profile) -> target name). Runs
        made before schema 19, so that a token limited to a target sees its history too.
        Runs that match no target, or several, keep no name. Returns how many were named."""
        named = 0
        with self._conn:
            for (address, profile), name in names.items():
                cur = self._conn.execute(
                    "UPDATE scan_run SET target_name = ? WHERE target_name IS NULL "
                    "AND target = ? AND profile IS ?",
                    (name, address, profile),
                )
                named += cur.rowcount
        return named

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
            "s.web, s.vhosts FROM service s JOIN asset a ON a.id = s.asset_id "
            "WHERE a.run_id = ? ORDER BY s.port, s.id",
            (run_id,),
        ).fetchall()
        return [_service(r) for r in rows]

    def findings_for_run(self, run_id: int) -> list[Finding]:
        """The findings recorded for a run, each with the service it was found on."""
        run = self.load_run(run_id)
        return [f for a in run.assets for f in a.findings] if run else []


def _targets_clause(targets: tuple[str, ...] | None, column: str) -> tuple[str, list[str]]:
    """SQL limiting `column` to names matching `targets` (glob patterns; None: no limit)."""
    if targets is None:
        return "", []
    if not targets:
        return " AND 0", []
    return " AND (" + " OR ".join(f"{column} GLOB ?" for _ in targets) + ")", list(targets)


def prefer_wal(path: str | Path) -> str | None:
    """At a service's start: the database (if there is one yet) in write-ahead logging,
    e.g. again after a backup — which is kept in the default mode — was restored."""
    if not Path(path).is_file():
        return None  # created later, by the first write, already in WAL
    try:
        with Storage(path) as store:
            return store.use_wal()
    except (StorageError, sqlite3.Error) as exc:
        log.warning("could not switch %s to write-ahead logging: %s", path, exc)
        return None


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
        vhosts=tuple(WebPage.from_dict(p) for p in json.loads(row["vhosts"] or "[]")),
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
        tried=row["tried"],
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


# What a change of each kind means, for the person reading the alert.
_WHY = {
    "scope": "what may be scanned changed",
    "target": "what is scanned, how or when changed",
    "token": "who may use ZuesScan changed",
}


def _config_alert(event: AuditEvent) -> Alert:
    """A change made in the dashboard (or with zues user), for whoever watches the webhook:
    one admin can widen what may be scanned, so the others should know at once."""
    kind, _, name = event.target.partition(":")
    action = str(event.detail.get("action", "changed"))
    extra = ""
    if kind == "token" and event.detail.get("role"):
        extra = f" (role {event.detail['role']})"
    why = _WHY.get(kind, "the configuration changed")
    if action.endswith("proposed"):
        why = "it waits for another admin's approval"
    elif action.endswith(("rejected", "withdrawn")):
        why = "nothing changed"
    elif event.detail.get("approved_by"):
        extra = f" (proposed by {event.detail['proposed_by']}, approved)"
    return Alert(
        "config_changed",
        {
            "kind": "config_changed",
            "text": (
                f"ZuesScan: {event.operator or 'someone'}: {action} — {kind} {name}{extra}: "
                f"{why}; see the audit trail"
            ),
            "what": kind,
            "name": name,
            "action": action,
            "by": event.operator,
            "engagement": event.engagement,
            "scope_sha256": event.scope_sha256,
        },
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
