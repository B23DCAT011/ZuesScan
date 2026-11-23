"""End-to-end CLI tests using a fake plugin and fake DNS injected via monkeypatch."""

import re
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, fake_resolver, lab_asset, lab_resolver

from reconkit import cli
from reconkit.plugins.base import ScanError, ScanResult
from reconkit.schema import Hop, RawOutput, ScanTarget, Service
from reconkit.storage import Storage

LAB_SCOPE = "scanme.lab\n10.0.0.0/24\n"


@pytest.fixture(autouse=True)
def _lab_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer DNS from the lab records: no test may depend on the real resolver."""
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", lab_resolver)
    monkeypatch.setattr("reconkit.scope.resolve_addresses", lab_resolver)


def _scope_file(tmp_path: Path, text: str = LAB_SCOPE) -> str:
    path = tmp_path / "scope.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def _runs(db: Path) -> list[tuple[str, str | None]]:
    """`(status, error)` of every run stored in `db`."""
    with Storage(db) as store:
        rows = store._conn.execute("SELECT status, error FROM scan_run ORDER BY id").fetchall()
    return [(r["status"], r["error"]) for r in rows]


def _count(db: Path, table: str) -> int:
    with Storage(db) as store:
        return int(store._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])


def test_scan_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"

    # Replace the real nmap plugin with a deterministic fake.
    fake = FakePlugin([lab_asset(Service(port=22, name="ssh", product="OpenSSH", version="7.4"))])
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert _runs(db) == [("completed", None)]
    assert "Scan run #1" in out
    assert "status=completed" in out
    assert "scanners: fake 1.0-fake" in out
    assert "evidence: 22/tcp open: scanner reported product 'OpenSSH'" in out
    assert "raw output kept: fake (fake-text, " in out
    assert "resolved: scanme.lab -> 10.0.0.5" in out
    assert "hosts: 1 " in out
    assert "scanme.lab (10.0.0.5)" in out
    assert "22/tcp" in out
    assert "OpenSSH 7.4" in out
    assert "CVE-2018-15473" in out
    assert fake.seen[0].addresses == ("10.0.0.5",)  # the plugin scanned the address


def test_range_scan_is_reported_and_stored_per_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    fake = FakePlugin(
        [
            lab_asset(Service(port=22, name="ssh"), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(host="10.0.0.7", ip="10.0.0.7"),  # up, nothing open
        ]
    )
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)

    code = cli.main(["scan", "10.0.0.0/24", "--scope", _scope_file(tmp_path), "--db", str(db)])
    out = capsys.readouterr().out

    assert code == 0
    assert "hosts: 2 responded of 256 addresses" in out
    # Each host has its own block; the port is listed under the host it belongs to.
    first, second = out.index("\n  10.0.0.5\n"), out.index("\n  10.0.0.7\n")
    assert first < out.index("22/tcp") < second
    assert "no open ports found" in out[second:]

    with Storage(db) as store:
        rows = store._conn.execute("SELECT host, ip FROM asset ORDER BY id").fetchall()
    assert [(r["host"], r["ip"]) for r in rows] == [
        ("10.0.0.5", "10.0.0.5"),
        ("10.0.0.7", "10.0.0.7"),
    ]


def test_range_scan_excludes_denied_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakePlugin([lab_asset(host="10.0.0.5", ip="10.0.0.5")])
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)
    scope = _scope_file(tmp_path, "10.0.0.0/24\n!10.0.0.1  # router\n")

    code = cli.main(["scan", "10.0.0.0/24", "--scope", scope, "--db", str(tmp_path / "x.db")])
    out = capsys.readouterr().out

    assert code == 0
    assert fake.seen[0].exclude == ("10.0.0.1",)
    assert "excluded (denylist): 10.0.0.1" in out
    assert "responded of 255 addresses" in out  # the denied address is not counted


def test_scan_refuses_out_of_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([]))
    code = cli.main(
        [
            "scan",
            "evil.example.com",
            "--scope",
            _scope_file(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
        ]
    )
    assert code == 3  # refused
    assert "refused" in capsys.readouterr().err


def test_scan_refuses_name_pointing_outside_the_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # G4: the name is in the allowlist, the machine behind it is not.
    fake = FakePlugin([])
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)
    monkeypatch.setattr(
        "reconkit.scope.resolve_addresses", fake_resolver({"scanme.lab": ["203.0.113.9"]})
    )
    db = tmp_path / "x.db"

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    err = capsys.readouterr().err

    assert code == 3
    assert "refused" in err
    assert "resolves to 203.0.113.9" in err
    assert fake.seen == []  # nothing was scanned
    assert _runs(db) == []  # a refusal is not a run: nothing was attempted


def test_scan_of_unresolvable_name_is_recorded_as_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([]))
    monkeypatch.setattr("reconkit.scope.resolve_addresses", fake_resolver({}))
    db = tmp_path / "x.db"

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    err = capsys.readouterr().err

    assert code == 4
    assert "scan failed: cannot resolve 'scanme.lab'" in err
    assert "recorded as failed run #1" in err
    ((status, error),) = _runs(db)
    assert status == "failed"
    assert error is not None and "cannot resolve 'scanme.lab'" in error


def test_out_of_scope_host_in_results_is_warned_about_and_not_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakePlugin(
        [
            lab_asset(host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(host="192.0.2.50", ip="192.0.2.50"),  # the tool strayed
        ]
    )
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)
    db = tmp_path / "out.db"

    code = cli.main(["scan", "10.0.0.0/24", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 0
    assert "outside the scope; not saved: 192.0.2.50" in captured.err
    assert "192.0.2.50" not in captured.out
    with Storage(db) as store:
        rows = store._conn.execute("SELECT ip FROM asset").fetchall()
    assert [r["ip"] for r in rows] == ["10.0.0.5"]


def test_scan_rejects_invalid_scope_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([]))
    scope = _scope_file(tmp_path, "scanme.lab\nnot a host\n")
    code = cli.main(["scan", "scanme.lab", "--scope", scope, "--db", str(tmp_path / "x.db")])
    assert code == 2  # bad input, same as a missing scope file
    err = capsys.readouterr().err
    assert "invalid scope file" in err
    assert "scope.txt:2" in err


def test_scan_failure_is_reported_and_recorded_as_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    error = ScanError("nmap exited with code 1", plugin="nmap", stderr="requires root\nQUITTING!")
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([], error=error))

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4  # scan failed
    assert "scan failed [nmap]: nmap exited with code 1" in captured.err
    assert "  | requires root" in captured.err  # the tool's own stderr is shown
    assert "Traceback" not in captured.err
    assert "Scan run" not in captured.out
    # G14: the failure is kept, with the tool's own words, and can never be mistaken
    # for a clean run: status says failed, and no host was stored.
    assert _runs(db) == [("failed", "nmap exited with code 1\nrequires root\nQUITTING!")]
    assert _count(db, "asset") == 0
    with Storage(db) as store:
        run = store.load_run(1)
    assert run is not None
    assert run.failed_plugin == "nmap"


def test_run_after_a_failed_one_gets_the_next_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    args = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]
    error = ScanError("nmap timed out", plugin="fake")
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([], error=error))
    assert cli.main(args) == 4
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
    assert cli.main(args) == 0

    assert "Scan run #2" in capsys.readouterr().out
    assert [status for status, _ in _runs(db)] == ["failed", "completed"]


def test_database_from_a_newer_reconkit_is_refused_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    with Storage(db) as store:
        store._conn.execute("INSERT INTO schema_version VALUES (999, 'later')")
        store._conn.commit()
    fake = FakePlugin([lab_asset()])
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])

    assert code == 1
    assert "schema v999" in capsys.readouterr().err
    assert fake.seen == []  # no point probing a target whose results cannot be saved


def test_scan_without_any_scanner_is_recorded_as_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([], available=False))

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    captured = capsys.readouterr()

    assert code == 4
    assert "scan failed: no scanner available: fake" in captured.err
    assert "Scan run" not in captured.out
    # "could not scan" must never be stored as "clean"
    assert _runs(db) == [("failed", "no scanner available: fake not installed or not on PATH")]
    with Storage(db) as store:
        run = store.load_run(1)
    assert run is not None
    assert run.skipped_plugins == ["fake"]


# --- `reconkit raw`: getting the evidence back out (G13) -------------------------


def _scan_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakePlugin) -> Path:
    db = tmp_path / "out.db"
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)
    cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])
    return db


def test_raw_prints_the_stored_output_and_nothing_else_on_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset()]))
    capfdbinary.readouterr()  # drop what `scan` printed

    code = cli.main(["raw", "1", "--db", str(db)])
    captured = capfdbinary.readouterr()

    assert code == 0
    assert captured.out == b"fake scan of 10.0.0.5\n"  # pipeable: output only
    assert b"command: fake 10.0.0.5" in captured.err
    assert b"verified" in captured.err


def test_raw_can_write_to_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset()]))
    out = tmp_path / "evidence.txt"

    assert cli.main(["raw", "1", "--db", str(db), "--out", str(out)]) == 0
    assert out.read_bytes() == b"fake scan of 10.0.0.5\n"


def test_raw_of_a_failed_run_shows_what_the_scanner_printed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    printed = RawOutput(plugin="fake", format="fake-text", command=("fake",), content="<broken")
    error = ScanError("unreadable output", plugin="fake", output=printed)
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([], error=error))
    out = tmp_path / "evidence.txt"

    assert cli.main(["raw", "1", "--db", str(db), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "<broken"


def test_raw_reports_missing_database_run_and_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "nope.db"
    assert cli.main(["raw", "1", "--db", str(missing)]) == 2
    assert "database not found" in capsys.readouterr().err
    assert not missing.exists()  # asking for evidence must not create a database

    error = ScanError("nmap timed out", plugin="fake")  # failed before printing anything
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([], error=error))
    capsys.readouterr()
    assert cli.main(["raw", "7", "--db", str(db)]) == 2
    assert "no run #7" in capsys.readouterr().err
    assert cli.main(["raw", "1", "--db", str(db)]) == 1
    assert "run #1 has no raw output stored" in capsys.readouterr().err


# --- --traceroute (M1) -------------------------------------------------------------


def test_traceroute_flag_reaches_the_plugin_and_route_is_shown_and_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    asset = lab_asset(Service(port=22, name="ssh"))
    asset.route = [Hop(ttl=1, ip="192.168.1.1"), Hop(ttl=3, ip="10.0.0.5")]
    fake = FakePlugin([asset])
    options: dict[str, Any] = {}

    def make(**kwargs: object) -> FakePlugin:
        options.update(kwargs)
        return fake

    monkeypatch.setattr("reconkit.scanning.NmapPlugin", make)
    db = tmp_path / "out.db"
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]

    assert cli.main([*argv, "--traceroute"]) == 0
    captured = capsys.readouterr()
    assert options["profile"].traceroute is True
    assert "route: 192.168.1.1 -> ? -> 10.0.0.5 (3 hops)" in captured.out
    assert "no route recorded" not in captured.err
    assert _count(db, "route_hop") == 2


def test_traceroute_is_off_unless_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options: dict[str, Any] = {}

    def make(**kwargs: object) -> FakePlugin:
        options.update(kwargs)
        return FakePlugin([lab_asset()])

    monkeypatch.setattr("reconkit.scanning.NmapPlugin", make)
    cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")])
    assert options["profile"].traceroute is False
    assert "route:" not in capsys.readouterr().out


def test_traceroute_that_recorded_nothing_is_explained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")]

    assert cli.main([*argv, "--traceroute"]) == 0  # still a good scan
    err = capsys.readouterr().err
    assert "no route recorded for 1 of 1 host(s)" in err
    assert "raw-socket privileges" in err


# --- runs / report (M1) ---------------------------------------------------------------


def test_runs_lists_what_was_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset(Service(port=22))]))
    capsys.readouterr()
    assert cli.main(["runs", "--db", str(db)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split()[:3] == ["ID", "STARTED", "(UTC)"]
    assert lines[1].split()[0] == "1"
    assert lines[1].split()[3:] == ["completed", "1", "1", "0", "scanme.lab"]


def test_runs_and_report_never_create_a_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "nope.db"
    assert cli.main(["runs", "--db", str(missing)]) == 2
    assert cli.main(["report", "--db", str(missing), "--html", str(tmp_path / "r.html")]) == 2
    assert "database not found" in capsys.readouterr().err
    assert not missing.exists()


def test_report_of_the_latest_run_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset(Service(port=22))]))
    _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset(Service(port=443))]))
    capsys.readouterr()
    out = tmp_path / "report.html"

    assert cli.main(["report", "--db", str(db), "--html", str(out)]) == 0
    assert "report of run #2 (scanme.lab, completed)" in capsys.readouterr().out
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert '"port":443' in page and '"port":22' not in page

    assert cli.main(["report", "--db", str(db), "--run", "1", "--html", str(out)]) == 0
    assert '"port":22' in out.read_text(encoding="utf-8")


def test_report_of_an_unknown_run_or_an_empty_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "empty.db"
    Storage(empty).close()
    out = str(tmp_path / "r.html")
    assert cli.main(["report", "--db", str(empty), "--html", out]) == 2
    assert "no run stored" in capsys.readouterr().err

    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset()]))
    capsys.readouterr()
    assert cli.main(["report", "--db", str(db), "--run", "9", "--html", out]) == 2
    assert "no run #9" in capsys.readouterr().err


def test_report_that_cannot_be_written_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset()]))
    capsys.readouterr()
    out = str(tmp_path / "no-such-dir" / "r.html")
    assert cli.main(["report", "--db", str(db), "--html", out]) == 1
    assert "cannot write" in capsys.readouterr().err


# --- scan profiles (G6, G7) -----------------------------------------------------------


def _capture_profile(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    options: dict[str, Any] = {}

    def make(**kwargs: object) -> FakePlugin:
        options.update(kwargs)
        return FakePlugin([lab_asset(Service(port=22))])

    monkeypatch.setattr("reconkit.scanning.NmapPlugin", make)
    return options


def test_scan_uses_the_chosen_profile_and_records_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options = _capture_profile(monkeypatch)
    db = tmp_path / "out.db"
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]

    assert cli.main([*argv, "--profile", "quick"]) == 0
    assert options["profile"].top_ports == 100
    assert "profile: quick (top 100 ports, -T4, timeout 5min)" in capsys.readouterr().out
    with Storage(db) as store:
        run = store.load_run(1)
    assert run is not None
    assert run.profile == "quick"
    assert run.profile_settings is not None and run.profile_settings["top_ports"] == 100


def test_flags_override_the_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options = _capture_profile(monkeypatch)
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")]
    flags = ["--profile", "full", "--ports", "22,80", "--timing", "3", "--max-rate", "100"]
    assert cli.main([*argv, *flags, "--no-traceroute", "--assume-up", "--timeout", "60"]) == 0
    profile = options["profile"]
    assert (profile.name, profile.ports, profile.timing) == ("full", "22,80", 3)
    assert (profile.max_rate, profile.traceroute, profile.assume_up) == (100, False, True)
    assert profile.timeout == 60


def test_bad_profile_or_setting_stops_before_anything_happens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _capture_profile(monkeypatch)
    db = tmp_path / "out.db"
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]

    assert cli.main([*argv, "--profile", "turbo"]) == 2
    assert "unknown profile 'turbo'; choose one of: quick, standard" in capsys.readouterr().err
    assert cli.main([*argv, "--ports", "-oN /tmp/x"]) == 2
    assert "invalid port list" in capsys.readouterr().err
    assert not db.exists()


def test_profile_from_a_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options = _capture_profile(monkeypatch)
    config = tmp_path / "reconkit.toml"
    config.write_text('[profiles.nightly]\nbase = "full"\ntiming = 3\n', encoding="utf-8")
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")]
    assert cli.main([*argv, "--config", str(config), "--profile", "nightly"]) == 0
    assert (options["profile"].name, options["profile"].timing) == ("nightly", 3)

    capsys.readouterr()
    assert cli.main(["profiles", "--config", str(config)]) == 0
    out = capsys.readouterr().out
    assert "standard  (default)" in out
    assert "nightly\n" in out
    assert "nmap -sV -T3 -p - --max-retries 3 --host-timeout 3600s --traceroute" in out


# --- CVE data (G8, G10) -------------------------------------------------------------------


def test_finding_shows_its_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    svc = Service(port=22, name="ssh", product="OpenSSH", version="7.4p1 Debian 10+deb9u7")
    _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset(svc)]))
    out = capsys.readouterr().out
    assert "[MEDIUM, tentative] OpenSSH username enumeration (CVE-2018-15473)" in out


def test_unusable_cve_file_stops_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
    db = tmp_path / "out.db"
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]
    assert cli.main([*argv, "--cve-db", str(tmp_path / "nope.json")]) == 2
    assert "CVE data file not found" in capsys.readouterr().err
    assert not db.exists()


# --- NVD cache (G9) ------------------------------------------------------------------------


def _fake_nvd(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make `cve sync` talk to canned NVD pages; return the URLs it asked for."""
    import json as _json

    from reconkit.cve.nvd import NvdClient

    page = _json.loads((Path(__file__).parent / "data" / "nvd_page.json").read_text("utf-8"))
    urls: list[str] = []

    def fetch(url: str, headers: dict[str, str]) -> object:
        urls.append(url)
        return page

    monkeypatch.setattr(
        cli,
        "NvdClient",
        lambda api_key=None: NvdClient(api_key=api_key, fetch=fetch, sleep=lambda _s: None),
    )
    # KEV and EPSS: canned files instead of downloads.
    import gzip

    from reconkit.cve import cache as cache_module
    from reconkit.cve.feeds import EPSS_URL, KEV_URL

    feeds = {
        KEV_URL: (Path(__file__).parent / "data" / "kev_sample.json").read_bytes(),
        EPSS_URL: gzip.compress(b"cve,epss,percentile\nCVE-2021-23017,0.2,0.9\n"),
    }
    monkeypatch.setattr(
        cli, "refresh_kev", lambda c: cache_module.refresh_kev(c, feeds.__getitem__)
    )
    monkeypatch.setattr(
        cli, "refresh_epss", lambda c: cache_module.refresh_epss(c, feeds.__getitem__)
    )
    return urls


def test_cve_sync_status_show(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    urls = _fake_nvd(monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    cache = str(tmp_path / "cve.db")

    assert cli.main(["cve", "sync", "--cache", cache, "--product", "cpe:2.3:a:f5:nginx"]) == 0
    captured = capsys.readouterr()
    assert "cpe:2.3:a:f5:nginx: 2 CVE(s) stored, 1 rejected removed (full download)" in captured.out
    assert "no NVD API key" in captured.err
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Af5%3Anginx" in urls[0]
    assert "CISA KEV catalog 2026.11.20: 2 known exploited CVEs" in captured.out
    assert "FIRST EPSS scores of ?: 1 CVEs" in captured.out

    assert cli.main(["cve", "status", "--cache", cache]) == 0
    out = capsys.readouterr().out
    assert "2 CVEs" in out and "cpe:2.3:a:f5:nginx: synced" in out

    assert cli.main(["cve", "show", "cve-2021-23017", "--cache", cache]) == 0
    out = capsys.readouterr().out
    assert "cvss_score: 7.7" in out
    assert "kev: exploited in the wild: in CISA KEV since 2026-01-15" in out
    assert "epss: 20.00% (percentile 90.0%)" in out
    assert "affects: f5:nginx >= 0.6.18, < 1.20.1" in out
    assert cli.main(["cve", "show", "CVE-1999-0001", "--cache", cache]) == 1


def test_cve_sync_refuses_a_product_that_is_not_a_cpe_prefix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "cve.db"
    assert cli.main(["cve", "sync", "--cache", str(cache), "--product", "nginx"]) == 2
    assert "CPE 2.3 prefix" in capsys.readouterr().err
    assert not cache.exists()


def test_cve_status_of_a_missing_cache(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["cve", "status", "--cache", str(tmp_path / "nope.db")]) == 2
    assert "reconkit cve sync" in capsys.readouterr().err


def test_scan_matches_against_the_nvd_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_nvd(monkeypatch)
    cache = str(tmp_path / "cve.db")
    cli.main(["cve", "sync", "--cache", cache])
    svc = Service(port=80, name="http", product="nginx", version="1.14.2")
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: FakePlugin([lab_asset(svc)]))
    capsys.readouterr()

    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")]
    assert cli.main([*argv, "--cve-cache", cache]) == 0
    out = capsys.readouterr().out
    assert "P1 [HIGH, firm] " in out and "(CVE-2021-23017)" in out
    assert "priority: known exploited (CISA KEV since 2026-01-15) | CVSS 7.7 | EPSS 20.0%" in out
    assert "Affected per NVD cache" in out

    assert cli.main([*argv, "--cve-cache", str(tmp_path / "nope.db")]) == 2
    assert "reconkit cve sync" in capsys.readouterr().err


def test_cve_sync_can_skip_the_feeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_nvd(monkeypatch)
    cache = str(tmp_path / "cve.db")
    assert cli.main(["cve", "sync", "--cache", cache, "--no-kev", "--no-epss"]) == 0
    out = capsys.readouterr().out
    assert "KEV" not in out and "EPSS" not in out


def test_feed_failure_keeps_what_was_downloaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit.cve.feeds import FeedError

    _fake_nvd(monkeypatch)

    def broken(cache: object) -> object:
        raise FeedError("cannot download https://example/kev.json: timed out")

    monkeypatch.setattr(cli, "refresh_kev", broken)
    cache = str(tmp_path / "cve.db")
    assert cli.main(["cve", "sync", "--cache", cache]) == 1
    assert "run the same command again" in capsys.readouterr().err
    assert cli.main(["cve", "status", "--cache", cache]) == 0
    assert "2 CVEs" in capsys.readouterr().out


# --- IPv6 (G22) ---------------------------------------------------------------------------


def test_ipv4_only_flag_and_notes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakePlugin([lab_asset()])
    monkeypatch.setattr("reconkit.scanning.NmapPlugin", lambda **_: fake)
    dual = fake_resolver({"scanme.lab": ["10.0.0.5", "2001:db8::5"]})
    monkeypatch.setattr("reconkit.scope.resolve_addresses", dual)
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")]

    assert cli.main(argv) == 3  # the AAAA address is not in the scope
    assert "resolves to 2001:db8::5" in capsys.readouterr().err
    assert cli.main([*argv, "--ipv4-only"]) == 0
    assert "note: IPv4 only" in capsys.readouterr().err
    assert fake.seen[-1].addresses == ("10.0.0.5",)


def test_raw_picks_one_of_several_outputs_by_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    class TwoRuns(FakePlugin):
        def scan(self, target: ScanTarget) -> ScanResult:
            result = super().scan(target)
            result.raw.append(RawOutput("fake", "fake-text", ("fake", "-6", "::1"), "v6 output\n"))
            return result

    db = _scan_once(tmp_path, monkeypatch, TwoRuns([lab_asset()]))
    out = capfdbinary.readouterr().out
    assert b"reconkit raw 1 --index 2 --db" in out

    assert cli.main(["raw", "1", "--db", str(db)]) == 2
    err = capfdbinary.readouterr().err
    assert b"has 2 raw outputs; pick one with --index" in err
    assert b"  2  fake     fake -6 ::1" in err
    assert cli.main(["raw", "1", "--db", str(db), "--index", "2"]) == 0
    assert capfdbinary.readouterr().out == b"v6 output\n"
    assert cli.main(["raw", "1", "--db", str(db), "--index", "3"]) == 1


def test_scan_summary_shows_the_most_urgent_findings_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit.schema import Finding

    asset = lab_asset(Service(port=80, name="http"))
    asset.findings = [
        Finding(
            asset="scanme.lab", title=f"issue {i}", rule_id=f"rule-{i}", service=asset.services[0]
        )
        for i in range(13)
    ]
    asset.findings[12].kev_added = "2025-01-01"  # the one to fix first
    _scan_once(tmp_path, monkeypatch, FakePlugin([asset]))
    out = capsys.readouterr().out
    assert len(re.findall(r"^    P[1-4] ", out, re.M)) == 10
    assert "P1 [INFO] issue 12" in out
    assert "... and 3 less urgent finding(s)" in out


def test_report_writes_json_and_sarif_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    svc = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
    db = _scan_once(tmp_path, monkeypatch, FakePlugin([lab_asset(svc)]))
    capsys.readouterr()
    out_json, out_sarif = tmp_path / "r.json", tmp_path / "r.sarif"
    argv = ["report", "--db", str(db), "--json", str(out_json), "--sarif", str(out_sarif)]
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert "JSON report of run #1" in out and "SARIF report of run #1" in out
    model = json.loads(out_json.read_text(encoding="utf-8"))
    assert model["format"] == "reconkit-report"
    assert model["hosts"][0]["findings"][0]["cve"] == "CVE-2018-15473"
    sarif = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-2018-15473"


def test_report_needs_an_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["report", "--db", str(tmp_path / "x.db")]) == 2
    assert "choose at least one output" in capsys.readouterr().err


def test_token_prints_the_secret_once_and_only_its_hash_for_the_config(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import hashlib

    assert cli.main(["token", "--name", "alice", "--role", "operator"]) == 0
    out = capsys.readouterr().out

    token = re.search(r"keep it secret\): (\S+)", out)
    assert token is not None and len(token.group(1)) >= 40
    digest = hashlib.sha256(token.group(1).encode()).hexdigest()
    assert f'sha256 = "{digest}"' in out
    assert 'name = "alice"' in out and 'role = "operator"' in out
    assert out.count(token.group(1)) == 1
