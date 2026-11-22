"""Tests for logging (G19)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver

from reconkit import cli, logs


@pytest.fixture(autouse=True)
def _reset_logging() -> object:
    yield
    logs.setup(0)  # leave the default (warnings only) for the next test


def test_verbosity_levels() -> None:
    for verbosity, level in ((0, logging.WARNING), (1, logging.INFO), (2, logging.DEBUG)):
        logs.setup(verbosity)
        (console,) = logging.getLogger("reconkit").handlers
        assert console.level == level


def test_json_lines_carry_the_extra_fields(tmp_path: Path) -> None:
    path = tmp_path / "reconkit.log"
    logs.setup(0, str(path), "json")
    logging.getLogger("reconkit.test").info("run #%d saved", 7, extra={"run_id": 7})
    for handler in logging.getLogger("reconkit").handlers:
        handler.flush()
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert record["message"] == "run #7 saved"
    assert (record["level"], record["logger"], record["run_id"]) == ("info", "reconkit.test", 7)
    assert record["time"].endswith("+00:00")


@pytest.fixture
def _lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    monkeypatch.setattr("reconkit.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr(cli, "NmapPlugin", lambda **_: FakePlugin([lab_asset()]))
    scope = tmp_path / "scope.txt"
    scope.write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
    return ["scan", "scanme.lab", "--scope", str(scope), "--db", str(tmp_path / "x.db")]


def test_quiet_by_default_verbose_on_request(
    _lab: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(_lab) == 0
    assert "authorised: addresses" not in capsys.readouterr().err
    assert cli.main([*_lab, "-v"]) == 0  # after the subcommand
    err = capsys.readouterr().err
    assert "scan of scanme.lab authorised: addresses 10.0.0.5" in err
    assert "fake: 1 host(s)" in err and "run #2 saved" in err
    assert cli.main(["-vv", *_lab]) == 0  # or before it


def test_log_file_gets_everything(
    _lab: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "scan.log"
    assert cli.main([*_lab, "--log-file", str(path)]) == 0
    text = path.read_text(encoding="utf-8")
    assert "DEBUG" in text and "reconkit.orchestrator" in text and "run #1 saved" in text
    assert "authorised" not in capsys.readouterr().err  # the console stays quiet


def test_unwritable_log_file(_lab: list[str], tmp_path: Path) -> None:
    assert cli.main([*_lab, "--log-file", str(tmp_path / "no" / "such.log")]) == 2


def test_nvd_requests_are_logged_without_the_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit.cve.nvd import NvdClient

    def fetch(url: str, headers: dict[str, str]) -> object:
        return {"totalResults": 0, "vulnerabilities": []}

    monkeypatch.setenv("NVD_API_KEY", "s3cr3t-key")
    monkeypatch.setattr(
        cli, "NvdClient", lambda api_key=None: NvdClient(api_key=api_key, fetch=fetch)
    )
    log_file = tmp_path / "sync.log"
    argv = ["cve", "sync", "--cache", str(tmp_path / "c.db"), "--no-kev", "--no-epss"]
    assert cli.main([*argv, "-vv", "--log-file", str(log_file)]) == 0
    logged = capsys.readouterr().err + log_file.read_text(encoding="utf-8")
    assert "GET https://services.nvd.nist.gov/rest/json/cves/2.0?" in logged
    assert "s3cr3t" not in logged
