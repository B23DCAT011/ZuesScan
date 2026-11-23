"""Tests for the SQLite storage repository."""

import sqlite3
from pathlib import Path

import pytest

from zues_scan.orchestrator import RunStatus, ScanRun
from zues_scan.schema import Asset, Finding, Hop, RawOutput, Service, Severity
from zues_scan.storage import _V1, SCHEMA_VERSION, Storage, StorageError

SSH = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
HTTP = Service(port=80, name="http", product="nginx", version="1.18.0")
NMAP_XML = RawOutput(
    plugin="nmap",
    format="nmap-xml",
    command=("nmap", "-sV", "-T4", "-oX", "-", "10.0.0.5"),
    content='<?xml version="1.0"?>\n<nmaprun><!-- máy chủ “thử” --></nmaprun>\n',
    stderr="Warning: something",
)


def _finding(host: str, service: Service | None, title: str = "OpenSSH 7.4") -> Finding:
    finding = Finding(
        asset=host,
        ip="10.0.0.5" if host == "scanme.lab" else host,  # as the orchestrator sets it
        title=title,
        severity=Severity.MEDIUM,
        service=service,
        cve="CVE-2018-15473",
    )
    finding.compute_fingerprint()
    return finding


def _make_run() -> ScanRun:
    asset = Asset(
        host="scanme.lab", ip="10.0.0.5", services=[SSH], findings=[_finding("scanme.lab", SSH)]
    )
    return ScanRun(
        "scanme.lab",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:05+00:00",
        assets=[asset],
        tool_versions={"nmap": "7.92"},
        raw_outputs=[NMAP_XML],
    )


def _store(tmp_path: Path) -> Storage:
    return Storage(tmp_path / "test.db")


def _count(store: Storage, table: str) -> int:
    return int(store._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])


def test_save_and_read_back_services(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        services = store.services_for_run(run_id)
    assert [s.port for s in services] == [22]
    assert services[0].product == "OpenSSH"


def test_save_and_read_back_findings(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        findings = store.findings_for_run(run_id)
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert findings[0].fingerprint.startswith("v2:")


def test_run_ids_increment(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        first = store.save_run(_make_run())
        second = store.save_run(_make_run())
    assert second == first + 1


def test_rollback_on_failure_leaves_no_partial_run(tmp_path: Path) -> None:
    """If writing a run fails midway, the whole transaction must roll back."""
    with _store(tmp_path) as store:
        # Make the findings insert blow up *after* the scan_run + asset rows were
        # inserted within the same transaction.
        def boom(*_: object, **__: object) -> None:
            raise RuntimeError("simulated failure mid-write")

        store._insert_findings = boom  # type: ignore[method-assign]
        try:
            store.save_run(_make_run())
        except RuntimeError:
            pass
        # Nothing should have been committed.
        assert _count(store, "scan_run") == 0
        assert _count(store, "asset") == 0
        assert _count(store, "scan_run_plugin") == 0


# --- a finding remembers its service (G5) ----------------------------------------


def test_finding_read_back_knows_its_service(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        (finding,) = store.findings_for_run(run_id)
    assert finding.service == SSH
    assert finding.asset == "scanme.lab"


def test_findings_point_at_the_service_of_their_own_host(tmp_path: Path) -> None:
    # Two hosts with the same port: each finding must come back with *its* host's
    # service, not just any row with port 22.
    other_ssh = Service(port=22, name="ssh", product="Dropbear", version="2019.78")
    run = ScanRun(
        "10.0.0.0/24",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:05+00:00",
        assets=[
            Asset(
                host="10.0.0.5",
                ip="10.0.0.5",
                services=[SSH, HTTP],
                findings=[_finding("10.0.0.5", HTTP, "nginx issue"), _finding("10.0.0.5", SSH)],
            ),
            Asset(
                host="10.0.0.7",
                ip="10.0.0.7",
                services=[other_ssh],
                findings=[_finding("10.0.0.7", other_ssh, "dropbear issue")],
            ),
        ],
    )
    with _store(tmp_path) as store:
        findings = store.findings_for_run(store.save_run(run))
    assert [(f.asset, f.title, f.service) for f in findings] == [
        ("10.0.0.5", "nginx issue", HTTP),
        ("10.0.0.5", "OpenSSH 7.4", SSH),
        ("10.0.0.7", "dropbear issue", other_ssh),
    ]


def test_rule_id_is_stored(tmp_path: Path) -> None:
    run = _make_run()
    finding = Finding(
        asset="scanme.lab", ip="10.0.0.5", title="Admin panel exposed", rule_id="exposed-admin"
    )
    run.assets[0].findings = [finding]
    with _store(tmp_path) as store:
        (loaded,) = store.findings_for_run(store.save_run(run))
    assert loaded.rule_id == "exposed-admin"
    assert loaded.cve is None
    assert loaded == finding  # fingerprinted on save, and read back identical


def test_finding_without_a_service_is_kept_as_such(tmp_path: Path) -> None:
    # e.g. a host-level finding from a tool that does not work per port.
    run = _make_run()
    run.assets[0].findings = [_finding("scanme.lab", None, "host-level issue")]
    with _store(tmp_path) as store:
        (finding,) = store.findings_for_run(store.save_run(run))
    assert finding.service is None


def test_fingerprint_survives_a_round_trip(tmp_path: Path) -> None:
    # With the service restored, recomputing the fingerprint gives the stored one:
    # what `feat/diff` will rely on.
    with _store(tmp_path) as store:
        (finding,) = store.findings_for_run(store.save_run(_make_run()))
    stored = finding.fingerprint
    assert finding.compute_fingerprint() == stored


# --- a run remembers how it went (G14) -------------------------------------------


def test_load_run_returns_what_was_saved(tmp_path: Path) -> None:
    run = _make_run()
    run.status = RunStatus.PARTIAL
    run.skipped_plugins = ["nuclei"]
    run.out_of_scope = ["192.0.2.50", "10.0.0.1"]
    with _store(tmp_path) as store:
        loaded = store.load_run(store.save_run(run))
    assert loaded is not None
    run.plan = None  # the one thing that is not stored yet
    assert loaded == run


def test_failed_run_is_stored_with_its_error_and_no_results(tmp_path: Path) -> None:
    run = ScanRun(
        "scanme.lab",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:05:00+00:00",
        status=RunStatus.FAILED,
        error="nmap timed out after 300s scanning scanme.lab",
        tool_versions={"nmap": "7.92"},
        failed_plugin="nmap",
    )
    with _store(tmp_path) as store:
        run_id = store.save_run(run)
        loaded = store.load_run(run_id)
        plugins = store._conn.execute(
            "SELECT name, status, version FROM scan_run_plugin"
        ).fetchall()
    assert loaded == run
    assert [tuple(p) for p in plugins] == [("nmap", "failed", "7.92")]


def test_unknown_run_status_is_rejected_by_the_database(tmp_path: Path) -> None:
    with _store(tmp_path) as store, pytest.raises(sqlite3.IntegrityError):
        store._conn.execute(
            "INSERT INTO scan_run (target, status, started_at, finished_at) "
            "VALUES ('x', 'clean', 'a', 'b')"
        )


def test_load_run_of_unknown_id_is_none(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        assert store.load_run(42) is None
        assert store.findings_for_run(42) == []


# --- integrity: cascade and indexes (G15) ----------------------------------------


def test_deleting_a_run_deletes_everything_under_it(tmp_path: Path) -> None:
    run = _make_run()
    run.skipped_plugins = ["nuclei"]
    run.out_of_scope = ["192.0.2.50"]
    with _store(tmp_path) as store:
        doomed = store.save_run(run)
        kept = store.save_run(_make_run())
        assert store.delete_run(doomed) is True
        assert store.delete_run(doomed) is False  # already gone
        assert store.load_run(doomed) is None
        assert store.load_run(kept) is not None
        # Only the surviving run's rows are left: no orphans.
        for table, left in [
            ("asset", 1),
            ("service", 1),
            ("finding", 1),
            ("scan_run_plugin", 1),
            ("scan_run_output", 1),
            ("scan_run_out_of_scope", 0),
        ]:
            assert _count(store, table) == left, table


def test_asset_cannot_point_at_a_missing_run(tmp_path: Path) -> None:
    with _store(tmp_path) as store, pytest.raises(sqlite3.IntegrityError):
        store._conn.execute("INSERT INTO asset (run_id, host) VALUES (999, 'ghost')")


def test_every_foreign_key_is_indexed(tmp_path: Path) -> None:
    """A delete or a join must not scan a whole child table (G15)."""
    with _store(tmp_path) as store:
        conn = store._conn
        tables = [
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        for table in tables:
            # The first column of every index on this table (primary key included).
            leading = set()
            for index in conn.execute(f"PRAGMA index_list({table})").fetchall():
                first = conn.execute(f"PRAGMA index_info({index['name']})").fetchone()
                leading.add(first["name"])
            for fk in conn.execute(f"PRAGMA foreign_key_list({table})").fetchall():
                assert fk["from"] in leading, f"{table}.{fk['from']} has no index"


# --- schema versioning and migration (G15) ---------------------------------------


def _make_v1_db(path: Path) -> None:
    """A database as ZuesScan wrote it before F7: one run, with a finding."""
    conn = sqlite3.connect(path)
    for statement in _V1:
        conn.execute(statement)
    conn.execute(
        "INSERT INTO scan_run VALUES (7, 'scanme.lab', '2026-01-01T00:00', '2026-01-01T00:05')"
    )
    conn.execute("INSERT INTO asset VALUES (3, 7, 'scanme.lab', '10.0.0.5')")
    conn.execute(
        "INSERT INTO service VALUES "
        "(11, 3, 22, 'tcp', 'open', 'ssh', 'OpenSSH', '7.4', 'cpe:/a:openbsd:openssh:7.4', NULL)"
    )
    conn.execute(
        "INSERT INTO finding VALUES "
        "(5, 3, 'OpenSSH 7.4', 'medium', 'CVE-2018-15473', 'desc', '', 'abc123')"
    )
    conn.commit()
    conn.close()


def test_new_database_is_created_at_the_current_version(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        assert store.schema_version() == SCHEMA_VERSION
        assert store.backup_path is None  # nothing to back up
        versions = store._conn.execute("SELECT version FROM schema_version").fetchall()
    assert [v["version"] for v in versions] == list(range(1, SCHEMA_VERSION + 1))


def test_reopening_a_current_database_changes_nothing(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
    with _store(tmp_path) as store:
        assert store.backup_path is None
        assert store.load_run(run_id) is not None
        assert _count(store, "schema_version") == SCHEMA_VERSION


def test_v1_database_is_migrated_with_its_data(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    _make_v1_db(db)

    with Storage(db) as store:
        assert store.schema_version() == SCHEMA_VERSION
        run = store.load_run(7)
        assert run is not None
        assert run.target == "scanme.lab"
        assert run.status is RunStatus.COMPLETED  # v1 only stored successful scans
        assert run.zues_version is None  # unknown, and not made up
        (asset,) = run.assets
        assert (asset.host, asset.ip) == ("scanme.lab", "10.0.0.5")
        assert [s.cpe for s in asset.services] == ["cpe:/a:openbsd:openssh:7.4"]
        (finding,) = asset.findings
        # An old fingerprint is kept as it is (scheme 1, no prefix), not re-labelled.
        assert finding.fingerprint == "abc123"
        assert finding.rule_id is None
        assert finding.service is None  # v1 never knew; the migration does not guess
        # New runs carry on from the old ids.
        assert store.save_run(_make_run()) == 8
        # The new constraints are really in force on the migrated tables.
        assert store.delete_run(7) is True
        assert _count(store, "asset") == 1


def test_migration_keeps_a_backup_of_the_old_database(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    _make_v1_db(db)

    with Storage(db) as store:
        assert store.backup_path == f"{db}.v1.bak"

    backup = sqlite3.connect(f"{db}.v1.bak")
    columns = [row[1] for row in backup.execute("PRAGMA table_info(scan_run)")]
    runs = backup.execute("SELECT id, target FROM scan_run").fetchall()
    backup.close()
    assert "status" not in columns  # still the old schema
    assert runs == [(7, "scanme.lab")]


def test_failed_migration_leaves_the_database_untouched(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    _make_v1_db(db)
    # An orphan row: a finding whose asset does not exist. v1 never enforced this at
    # rest, so a real database could contain one; the migration must not bless it.
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO finding VALUES (6, 999, 'orphan', 'low', NULL, '', '', 'zzz')")
    conn.commit()
    conn.close()

    with pytest.raises(StorageError, match="pointing at missing rows"):
        Storage(db)

    conn = sqlite3.connect(db)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    columns = [row[1] for row in conn.execute("PRAGMA table_info(scan_run)")]
    n_findings = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    conn.close()
    assert "schema_version" not in tables  # rolled back entirely: still a v1 database
    assert "status" not in columns
    assert n_findings == 2


def test_database_from_a_newer_zues_is_refused(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store._conn.execute("INSERT INTO schema_version VALUES (?, 'later')", (SCHEMA_VERSION + 1,))
        store._conn.commit()
    with pytest.raises(StorageError, match="upgrade ZuesScan"):
        _store(tmp_path)


def test_file_that_is_not_a_database_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "notes.db"
    path.write_text("this is not a SQLite database, just some text\n" * 50, encoding="utf-8")
    with pytest.raises(StorageError, match="cannot use database"):
        Storage(path)


# --- evidence: raw scanner output (G13) ------------------------------------------


def test_raw_output_comes_back_exactly_as_it_went_in(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        (output,) = store.outputs_for_run(run_id)
    assert output == NMAP_XML  # content, command, stderr: nothing lost, non-ASCII included
    assert output.sha256 == NMAP_XML.sha256


def test_raw_output_is_stored_compressed_with_its_hash(tmp_path: Path) -> None:
    big = RawOutput(plugin="nmap", format="nmap-xml", command=("nmap",), content="<port/>" * 5000)
    run = _make_run()
    run.raw_outputs = [big]
    with _store(tmp_path) as store:
        store.save_run(run)
        row = store._conn.execute(
            "SELECT size, sha256, LENGTH(content) AS stored FROM scan_run_output"
        ).fetchone()
    assert row["size"] == 35000
    assert row["sha256"] == big.sha256
    assert row["stored"] < 1000  # zlib: repetitive XML shrinks a lot


def test_tampered_raw_output_is_refused(tmp_path: Path) -> None:
    import zlib

    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        # Someone edits the evidence after the fact (valid zlib, different text).
        store._conn.execute(
            "UPDATE scan_run_output SET content = ?",
            (zlib.compress(b"<nmaprun>nothing</nmaprun>"),),
        )
        store._conn.commit()
        with pytest.raises(StorageError, match="does not match its stored SHA-256"):
            store.outputs_for_run(run_id)


def test_damaged_raw_output_is_refused(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run_id = store.save_run(_make_run())
        store._conn.execute("UPDATE scan_run_output SET content = ?", (b"not zlib at all",))
        store._conn.commit()
        with pytest.raises(StorageError, match="unreadable"):
            store.load_run(run_id)


def test_run_without_raw_output_has_none(tmp_path: Path) -> None:
    run = _make_run()
    run.raw_outputs = []
    with _store(tmp_path) as store:
        assert store.outputs_for_run(store.save_run(run)) == []


def test_finding_evidence_is_stored(tmp_path: Path) -> None:
    run = _make_run()
    run.assets[0].findings[0].evidence = "22/tcp open: scanner reported product 'OpenSSH'"
    with _store(tmp_path) as store:
        (finding,) = store.findings_for_run(store.save_run(run))
    assert finding.evidence == "22/tcp open: scanner reported product 'OpenSSH'"


# --- route (traceroute hops), schema v5 ----------------------------------------------


def test_route_comes_back_in_order(tmp_path: Path) -> None:
    run = _make_run()
    run.assets[0].route = [
        Hop(ttl=1, ip="192.168.1.1", rtt_ms=0.52, name="gateway.lan"),
        Hop(ttl=3, ip="10.0.0.1", rtt_ms=None),  # gap at ttl 2, untimed hop
        Hop(ttl=4, ip="10.0.0.5", rtt_ms=3.4),
    ]
    with _store(tmp_path) as store:
        loaded = store.load_run(store.save_run(run))
    assert loaded is not None
    assert loaded.assets[0].route == run.assets[0].route


def test_host_without_route_has_none(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        loaded = store.load_run(store.save_run(_make_run()))
    assert loaded is not None
    assert loaded.assets[0].route == []


def test_one_hop_per_ttl(tmp_path: Path) -> None:
    run = _make_run()
    run.assets[0].route = [Hop(ttl=1, ip="192.168.1.1"), Hop(ttl=1, ip="172.16.0.1")]
    with _store(tmp_path) as store:
        with pytest.raises(sqlite3.IntegrityError):
            store.save_run(run)
        assert _count(store, "scan_run") == 0  # the whole run was rolled back


def test_route_is_deleted_with_its_run(tmp_path: Path) -> None:
    run = _make_run()
    run.assets[0].route = [Hop(ttl=1, ip="192.168.1.1")]
    with _store(tmp_path) as store:
        store.delete_run(store.save_run(run))
        assert _count(store, "route_hop") == 0


# --- list of runs (for `zues runs` / `report`) ------------------------------------


def test_list_runs_newest_first_with_counts(tmp_path: Path) -> None:
    failed = ScanRun("10.0.0.9", "2026-01-02T00:00:00+00:00", "2026-01-02T00:00:01+00:00")
    failed.status, failed.error = RunStatus.FAILED, "nmap timed out"
    with _store(tmp_path) as store:
        assert store.list_runs() == []
        assert store.latest_run_id() is None
        first = store.save_run(_make_run())
        second = store.save_run(failed)
        runs = store.list_runs()
        assert store.latest_run_id() == second
        assert [(r.id, r.status, r.hosts, r.services, r.findings) for r in runs] == [
            (second, RunStatus.FAILED, 0, 0, 0),
            (first, RunStatus.COMPLETED, 1, 1, 1),
        ]
        assert [r.id for r in store.list_runs(limit=1)] == [second]


def test_profile_is_stored_with_the_run(tmp_path: Path) -> None:
    run = _make_run()
    run.profile, run.profile_settings = "full", {"ports": "-", "timing": 4, "traceroute": True}
    with _store(tmp_path) as store:
        loaded = store.load_run(store.save_run(run))
        assert loaded is not None
        assert (loaded.profile, loaded.profile_settings) == (run.profile, run.profile_settings)
        bare = store.load_run(store.save_run(_make_run()))
        assert bare is not None and (bare.profile, bare.profile_settings) == (None, None)


def test_finding_confidence_is_stored(tmp_path: Path) -> None:
    from zues_scan.schema import Confidence

    run = _make_run()
    run.assets[0].findings[0].confidence = Confidence.TENTATIVE
    with _store(tmp_path) as store:
        (finding,) = store.findings_for_run(store.save_run(run))
    assert finding.confidence == Confidence.TENTATIVE


def test_finding_risk_facts_are_stored(tmp_path: Path) -> None:
    run = _make_run()
    f = run.assets[0].findings[0]
    f.cvss_score, f.cvss_vector = 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    f.cwe, f.kev_added, f.epss = ("CWE-362", "CWE-200"), "2024-01-01", 0.98675
    with _store(tmp_path) as store:
        (back,) = store.findings_for_run(store.save_run(run))
        (bare,) = store.findings_for_run(store.save_run(_make_run()))
    assert (back.cvss_score, back.cvss_vector, back.cwe) == (f.cvss_score, f.cvss_vector, f.cwe)
    assert (back.kev_added, back.epss) == ("2024-01-01", 0.98675)
    assert (bare.cvss_score, bare.cwe, bare.kev_added, bare.epss) == (None, (), None, None)


def test_run_notes_are_stored(tmp_path: Path) -> None:
    run = _make_run()
    run.notes = ["nmap: no host responded for x over IPv6"]
    with _store(tmp_path) as store:
        loaded = store.load_run(store.save_run(run))
        bare = store.load_run(store.save_run(_make_run()))
    assert loaded is not None and loaded.notes == run.notes
    assert bare is not None and bare.notes == []
