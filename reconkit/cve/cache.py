"""Local NVD cache (SQLite) and the CVE source that reads it (G9).

`reconkit cve sync` fills the cache from the NVD API; scans then match against it
offline — no scan ever waits on, or leaks its targets to, a remote service. The cache
is a separate file from the scan database: it is public data, can be shared between
machines, and is rebuilt at will.

    cve        one row per CVE: description, severity, CVSS, CWE, dates
    cve_range  the products / versions it affects (NVD cpeMatch), indexed by product
    kev        CISA's Known Exploited Vulnerabilities (catalog, plus NVD's own copy)
    epss       FIRST EPSS scores, all CVEs, replaced daily
    feed_state when the KEV catalog / EPSS scores were last downloaded
    sync_state when each download scope ("all", or one product) was last brought up
               to date, so the next sync asks NVD only for what changed since
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from reconkit.cve.cpe import Cpe
from reconkit.cve.feeds import EpssScore, FetchBytes, KevEntry, http_get, parse_epss, parse_kev
from reconkit.cve.match import affected_range, identify, to_finding
from reconkit.cve.nvd import NvdClient, NvdEntry, parse_cve
from reconkit.cve.records import AffectedRange, CveRecord
from reconkit.schema import Finding, Service, Severity

CACHE_VERSION = 2
SCOPE_ALL = "all"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS cve (
        id             TEXT PRIMARY KEY,
        published      TEXT,
        last_modified  TEXT,
        status         TEXT,
        title          TEXT NOT NULL,
        description    TEXT NOT NULL,
        severity       TEXT NOT NULL,
        cvss_version   TEXT,
        cvss_score     REAL,
        cvss_vector    TEXT,
        cwe            TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cve_range (
        cve_id      TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
        part        TEXT NOT NULL,
        vendor      TEXT NOT NULL,
        product     TEXT NOT NULL,
        version     TEXT,
        "update"    TEXT,
        start_incl  TEXT,
        start_excl  TEXT,
        end_incl    TEXT,
        end_excl    TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_range_product ON cve_range(product)",
    "CREATE INDEX IF NOT EXISTS idx_range_cve ON cve_range(cve_id)",
    """
    CREATE TABLE IF NOT EXISTS kev (
        cve_id      TEXT PRIMARY KEY,
        date_added  TEXT NOT NULL,
        due_date    TEXT,
        ransomware  INTEGER NOT NULL DEFAULT 0,
        name        TEXT NOT NULL DEFAULT '',
        source      TEXT NOT NULL CHECK (source IN ('cisa', 'nvd'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS epss (
        cve_id      TEXT PRIMARY KEY,
        score       REAL NOT NULL,
        percentile  REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feed_state (
        feed        TEXT PRIMARY KEY,
        fetched_at  TEXT NOT NULL,
        version     TEXT,
        rows        INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sync_state (
        scope      TEXT PRIMARY KEY,
        synced_at  TEXT NOT NULL,
        changed    INTEGER NOT NULL
    )
    """,
)


class CacheError(Exception):
    """The CVE cache cannot be used."""


@dataclass(frozen=True, slots=True)
class SyncResult:
    scope: str
    changed: int  # CVEs added or updated
    removed: int  # CVEs NVD now rejects
    since: str | None  # None: a full download


@dataclass(frozen=True, slots=True)
class CacheStatus:
    cves: int
    ranges: int
    scopes: dict[str, str]  # scope -> last sync time


class CveCache:
    """The SQLite file holding the NVD data."""

    def __init__(self, path: str | Path, *, create: bool = False) -> None:
        self.path = Path(path)
        if not create and not self.path.is_file():
            raise CacheError(
                f"CVE cache not found: {self.path}. Fill it first: reconkit cve sync "
                f"--cache {self.path}"
            )
        try:
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > CACHE_VERSION:
                raise CacheError(f"{self.path} was written by a newer ReconKit (cache v{version})")
            with self._conn:
                for statement in _SCHEMA:
                    self._conn.execute(statement)
                self._conn.execute(f"PRAGMA user_version = {CACHE_VERSION}")
        except sqlite3.Error as exc:
            raise CacheError(f"cannot use CVE cache {self.path}: {exc}") from exc

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CveCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- writing ---------------------------------------------------------------------

    def store(self, entries: list[NvdEntry], rejected: list[str]) -> None:
        """Insert or replace CVEs (with all their ranges) and drop rejected ones."""
        with self._conn:
            for cve_id in rejected:
                self._conn.execute("DELETE FROM cve WHERE id = ?", (cve_id,))
            for e in entries:
                r = e.record
                self._conn.execute("DELETE FROM cve WHERE id = ?", (r.id,))  # and its ranges
                self._conn.execute(
                    "INSERT INTO cve (id, published, last_modified, status, title, description,"
                    " severity, cvss_version, cvss_score, cvss_vector, cwe)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        r.id,
                        e.published,
                        e.last_modified,
                        e.status,
                        r.title,
                        r.description,
                        str(r.severity),
                        e.cvss_version,
                        e.cvss_score,
                        e.cvss_vector,
                        ",".join(e.cwe),
                    ),
                )
                self._conn.executemany(
                    'INSERT INTO cve_range (cve_id, part, vendor, product, version, "update",'
                    " start_incl, start_excl, end_incl, end_excl)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            r.id,
                            a.cpe.part,
                            a.cpe.vendor,
                            a.cpe.product,
                            a.cpe.version,
                            a.cpe.update,
                            a.start_including,
                            a.start_excluding,
                            a.end_including,
                            a.end_excluding,
                        )
                        for a in r.affects
                    ],
                )
                if r.kev_added:
                    # NVD's copy of the KEV listing; the catalog itself takes precedence.
                    self._conn.execute(
                        "INSERT OR IGNORE INTO kev (cve_id, date_added, source) "
                        "VALUES (?, ?, 'nvd')",
                        (r.id, r.kev_added),
                    )

    def replace_kev(self, version: str, entries: list[KevEntry], at: datetime) -> None:
        """Replace the KEV catalog (NVD's copies of it are kept for CVEs it lacks)."""
        with self._conn:
            self._conn.execute("DELETE FROM kev WHERE source = 'cisa'")
            self._conn.executemany(
                "INSERT OR REPLACE INTO kev (cve_id, date_added, due_date, ransomware, name, "
                "source) VALUES (?, ?, ?, ?, ?, 'cisa')",
                [(e.cve, e.added, e.due, int(e.ransomware), e.name) for e in entries],
            )
            self._mark_feed("kev", at, version, len(entries))

    def replace_epss(self, date: str | None, scores: list[EpssScore], at: datetime) -> None:
        """Replace every EPSS score with a new day's scores."""
        with self._conn:
            self._conn.execute("DELETE FROM epss")
            self._conn.executemany(
                "INSERT OR REPLACE INTO epss (cve_id, score, percentile) VALUES (?, ?, ?)",
                [(s.cve, s.score, s.percentile) for s in scores],
            )
            self._mark_feed("epss", at, date, len(scores))

    def _mark_feed(self, feed: str, at: datetime, version: str | None, rows: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO feed_state (feed, fetched_at, version, rows) "
            "VALUES (?, ?, ?, ?)",
            (feed, at.isoformat(), version, rows),
        )

    def feeds(self) -> dict[str, tuple[str, str | None, int]]:
        """feed -> (fetched at, version or score date, rows)."""
        return {
            r["feed"]: (r["fetched_at"], r["version"], r["rows"])
            for r in self._conn.execute("SELECT * FROM feed_state ORDER BY feed")
        }

    def mark_synced(self, scope: str, at: datetime, changed: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO sync_state (scope, synced_at, changed) VALUES (?, ?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET synced_at = excluded.synced_at, "
                "changed = excluded.changed",
                (scope, at.isoformat(), changed),
            )

    # --- reading ---------------------------------------------------------------------

    def last_sync(self, scope: str) -> datetime | None:
        row = self._conn.execute(
            "SELECT synced_at FROM sync_state WHERE scope = ?", (scope,)
        ).fetchone()
        return None if row is None else datetime.fromisoformat(row["synced_at"])

    def status(self) -> CacheStatus:
        cves = int(self._conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
        ranges = int(self._conn.execute("SELECT COUNT(*) FROM cve_range").fetchone()[0])
        scopes = {
            r["scope"]: r["synced_at"]
            for r in self._conn.execute("SELECT scope, synced_at FROM sync_state ORDER BY scope")
        }
        return CacheStatus(cves=cves, ranges=ranges, scopes=scopes)

    def records_for_product(self, product: str) -> list[CveRecord]:
        """Every CVE with a range for `product`, carrying only those ranges."""
        rows = self._conn.execute(
            "SELECT c.id, c.title, c.description, c.severity, c.cvss_score, c.cvss_vector,"
            " c.cwe, k.date_added AS kev_added, e.score AS epss,"
            ' r.part, r.vendor, r.product, r.version, r."update",'
            " r.start_incl, r.start_excl, r.end_incl, r.end_excl"
            " FROM cve_range r JOIN cve c ON c.id = r.cve_id"
            " LEFT JOIN kev k ON k.cve_id = c.id LEFT JOIN epss e ON e.cve_id = c.id"
            " WHERE r.product = ? ORDER BY c.id",
            (product,),
        ).fetchall()
        records: dict[str, tuple[sqlite3.Row, list[AffectedRange]]] = {}
        for row in rows:
            ranges = records.setdefault(row["id"], (row, []))[1]
            ranges.append(
                AffectedRange(
                    cpe=Cpe(
                        part=row["part"],
                        vendor=row["vendor"],
                        product=row["product"],
                        version=row["version"],
                        update=row["update"],
                    ),
                    start_including=row["start_incl"],
                    start_excluding=row["start_excl"],
                    end_including=row["end_incl"],
                    end_excluding=row["end_excl"],
                )
            )
        return [
            CveRecord(
                id=row["id"],
                severity=Severity(row["severity"]),
                affects=tuple(ranges),
                title=row["title"],
                description=row["description"],
                cvss_score=row["cvss_score"],
                cvss_vector=row["cvss_vector"],
                cwe=tuple(c for c in row["cwe"].split(",") if c),
                kev_added=row["kev_added"],
                epss=row["epss"],
            )
            for row, ranges in records.values()
        ]

    def details(self, cve_id: str) -> dict[str, Any] | None:
        """The stored fields of one CVE (for `reconkit cve show`)."""
        row = self._conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        kev = self._conn.execute(
            "SELECT date_added, due_date, ransomware, source FROM kev WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        if kev is not None:
            data["kev"] = (
                f"exploited in the wild: in CISA KEV since {kev['date_added']}"
                + (f", fix due {kev['due_date']}" if kev["due_date"] else "")
                + (", used in ransomware campaigns" if kev["ransomware"] else "")
            )
        epss = self._conn.execute(
            "SELECT score, percentile FROM epss WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if epss is not None:
            data["epss"] = f"{epss['score']:.2%} (percentile {epss['percentile']:.1%})"
        data["affects"] = [
            dict(r)
            for r in self._conn.execute(
                'SELECT part, vendor, product, version, "update", start_incl, start_excl,'
                " end_incl, end_excl FROM cve_range WHERE cve_id = ?",
                (cve_id,),
            )
        ]
        return data


def sync(
    cache: CveCache,
    client: NvdClient,
    *,
    product: str | None = None,
    full: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    progress: Callable[[int, int], None] | None = None,
) -> SyncResult:
    """Bring the cache up to date with NVD, for everything or for one product.

    The first sync of a scope downloads all of it; later ones only what NVD changed
    since the previous sync began (minus an hour, for clock drift). The sync time is
    recorded only once every page is stored: an interrupted sync is simply rerun.
    """
    scope = product or SCOPE_ALL
    started = now()
    previous = None if full else cache.last_sync(scope)
    since = previous - timedelta(hours=1) if previous is not None else None
    changed = removed = 0
    for page in client.pages(
        product=product, modified_since=since, until=started, progress=progress
    ):
        entries: list[NvdEntry] = []
        rejected: list[str] = []
        for raw in page:
            entry = parse_cve(raw)
            if entry is None:
                if raw.get("id"):
                    rejected.append(str(raw["id"]))
                continue
            entries.append(entry)
        cache.store(entries, rejected)
        changed += len(entries)
        removed += len(rejected)
    cache.mark_synced(scope, started, changed)
    return SyncResult(
        scope=scope,
        changed=changed,
        removed=removed,
        since=None if since is None else since.isoformat(),
    )


class NvdCveSource:
    """CVE source backed by the local NVD cache."""

    def __init__(self, cache: CveCache) -> None:
        self.cache = cache
        synced = cache.status().scopes
        latest = max(synced.values()) if synced else None
        self.name = f"NVD cache (synced {latest[:10]})" if latest else "NVD cache"

    def find(self, service: Service, asset_host: str) -> list[Finding]:
        software = identify(service)
        if software is None:
            return []
        findings = []
        for record in self.cache.records_for_product(software.product):
            matched = affected_range(software, record)
            if matched is not None:
                findings.append(
                    to_finding(service, asset_host, software, record, matched, self.name)
                )
        return findings


def refresh_kev(
    cache: CveCache,
    fetch: FetchBytes = http_get,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[str, int]:
    """Download the KEV catalog into the cache; return (catalog version, entries)."""
    from reconkit.cve.feeds import KEV_URL

    version, entries = parse_kev(fetch(KEV_URL))
    cache.replace_kev(version, entries, now())
    return version, len(entries)


def refresh_epss(
    cache: CveCache,
    fetch: FetchBytes = http_get,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[str | None, int]:
    """Download today's EPSS scores into the cache; return (score date, scores)."""
    from reconkit.cve.feeds import EPSS_URL

    date, scores = parse_epss(fetch(EPSS_URL))
    cache.replace_epss(date, scores, now())
    return date, len(scores)
