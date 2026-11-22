"""End-to-end CLI tests using a fake plugin and fake DNS injected via monkeypatch."""

from pathlib import Path

import pytest
from conftest import FakePlugin, fake_resolver, lab_asset, lab_resolver

from reconkit import cli
from reconkit.plugins.base import ScanError
from reconkit.schema import Hop, RawOutput, Service
from reconkit.storage import Storage

LAB_SCOPE = "scanme.lab\n10.0.0.0/24\n"


@pytest.fixture(autouse=True)
def _lab_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer DNS from the lab records: no test may depend on the real resolver."""
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", lab_resolver)


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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)

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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)

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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([]))
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)
    monkeypatch.setattr(
        "reconkit.scope.resolve_ipv4", fake_resolver({"scanme.lab": ["203.0.113.9"]})
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([]))
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", fake_resolver({}))
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([]))
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([], error=error))

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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([], error=error))
    assert cli.main(args) == 4
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)

    code = cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)])

    assert code == 1
    assert "schema v999" in capsys.readouterr().err
    assert fake.seen == []  # no point probing a target whose results cannot be saved


def test_scan_without_any_scanner_is_recorded_as_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "out.db"
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([], available=False))

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
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: fake)
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
    options: dict[str, object] = {}

    def make(**kwargs: object) -> FakePlugin:
        options.update(kwargs)
        return fake

    monkeypatch.setattr(cli, "NmapPlugin", make)
    db = tmp_path / "out.db"
    argv = ["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(db)]

    assert cli.main([*argv, "--traceroute"]) == 0
    captured = capsys.readouterr()
    assert options["traceroute"] is True
    assert "route: 192.168.1.1 -> ? -> 10.0.0.5 (3 hops)" in captured.out
    assert "no route recorded" not in captured.err
    assert _count(db, "route_hop") == 2


def test_traceroute_is_off_unless_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options: dict[str, object] = {}

    def make(**kwargs: object) -> FakePlugin:
        options.update(kwargs)
        return FakePlugin([lab_asset()])

    monkeypatch.setattr(cli, "NmapPlugin", make)
    cli.main(["scan", "scanme.lab", "--scope", _scope_file(tmp_path), "--db", str(tmp_path / "d")])
    assert options["traceroute"] is False
    assert "route:" not in capsys.readouterr().out


def test_traceroute_that_recorded_nothing_is_explained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
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
