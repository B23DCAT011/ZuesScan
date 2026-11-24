"""The worker's job: scan a configured target, record it, alert on what changed.

No Redis here: the job is a plain function, run directly. The queue tests run it
through RQ (test_server_queue.py).
"""

from __future__ import annotations

import json
import logging
import urllib.error
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver

from zues_scan.schema import Service
from zues_scan.server import notify
from zues_scan.server.config import ConfigError, load_config
from zues_scan.server.jobs import scan_target, spec_for
from zues_scan.storage import Storage

VSFTPD = Service(port=21, name="ftp", product="vsftpd", version="2.3.4")  # CVE-2011-2523: P2
OPENSSH = Service(port=22, name="ssh", product="OpenSSH", version="7.4")  # CVE-2018-15473: P4


@pytest.fixture(autouse=True)
def _lab_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_ipv4", lab_resolver)
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)


Posted = list[tuple[str, dict[str, Any], dict[str, str]]]


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> Posted:
    """Every webhook delivery (URL, decoded body, headers), instead of a real HTTP POST."""
    calls: Posted = []

    def record(url: str, body: bytes, headers: dict[str, str]) -> None:
        calls.append((url, json.loads(body), headers))

    monkeypatch.setattr("zues_scan.server.notify.http_post", record)
    return calls


def service_config(
    tmp_path: Path, *, target: str = "scanme.lab", min_priority: str = "P2", webhook: bool = True
) -> str:
    (tmp_path / "scope.txt").write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
    d = tmp_path.as_posix()
    notify_table = f'[notify]\nmin_priority = "{min_priority}"\n'
    if webhook:
        notify_table += 'webhook = "https://hooks.example.com/T0"\n'
    path = tmp_path / "service.toml"
    path.write_text(
        f'[service]\ndb = "{d}/zues.db"\n\n'
        f'[[targets]]\nname = "lab"\ntarget = "{target}"\nscope = "{d}/scope.txt"\n'
        'profile = "quick"\nengagement = "PT-1"\n\n' + notify_table,
        encoding="utf-8",
    )
    return str(path)


def use_scanner(monkeypatch: pytest.MonkeyPatch, *services: Service) -> FakePlugin:
    fake = FakePlugin([lab_asset(*services)])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: fake)
    return fake


def test_the_spec_comes_from_the_config_not_from_the_request(tmp_path: Path) -> None:
    config = load_config(service_config(tmp_path))
    spec = spec_for(config, config.target("lab"), "alice")

    assert (spec.target, spec.profile, spec.engagement) == ("scanme.lab", "quick", "PT-1")
    assert spec.db == config.db and spec.scope == config.target("lab").scope
    assert spec.operator == "alice"


def test_a_job_scans_records_and_alerts_on_new_urgent_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    use_scanner(monkeypatch, VSFTPD, OPENSSH)
    config = service_config(tmp_path)

    summary = scan_target(config, "lab", "alice")

    assert summary["code"] == 0 and summary["run_id"] == 1
    assert summary["status"] == "completed" and summary["target"] == "lab"
    assert summary["alerts"] == 1  # vsftpd (P2); OpenSSH is only P4
    with Storage(tmp_path / "zues.db") as store:
        run = store.load_run(1)
    assert run is not None
    assert (run.operator, run.engagement, run.profile) == ("alice", "PT-1", "quick")
    [(url, payload, headers)] = posted
    assert url == "https://hooks.example.com/T0"
    assert headers["X-ZuesScan-Event"] == "run" and headers["X-ZuesScan-Delivery"] == "1"
    assert payload["target"] == "lab" and payload["run_id"] == 1
    assert payload["text"].splitlines() == [
        "ZuesScan: run #1 of lab needs attention",
        "• NEW P2: vsftpd 2.3.4 backdoor command execution on scanme.lab (CVSS 9.8)",
    ]
    [item] = payload["items"]
    assert (item["kind"], item["cve"], item["priority"]) == ("new", "CVE-2011-2523", "P2")


def test_nothing_new_means_no_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    use_scanner(monkeypatch, VSFTPD)
    config = service_config(tmp_path)

    scan_target(config, "lab", "alice")
    second = scan_target(config, "lab", "alice")

    assert second["code"] == 0 and second["alerts"] == 0
    assert len(posted) == 1  # only the first run's


def test_a_fake_fix_is_alerted_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    use_scanner(monkeypatch, VSFTPD, OPENSSH)
    config = service_config(tmp_path, min_priority="P4")
    scan_target(config, "lab", "alice")
    with Storage(tmp_path / "zues.db") as store:
        [vsftpd] = [f for f in store.inventory_findings() if f.cve == "CVE-2011-2523"]
        store.decide_finding(vsftpd.id, "claim_fixed", actor="bob", note="patched")

    summary = scan_target(config, "lab", "scheduler")

    assert summary["alerts"] == 1
    lines = posted[-1][1]["text"].splitlines()
    assert lines[1] == (
        "• FAKE FIX: vsftpd 2.3.4 backdoor command execution on scanme.lab was claimed "
        "fixed, still there"
    )
    # The first run alerted on both new findings, most urgent first (min_priority P4).
    first = [i["priority"] for i in posted[0][1]["items"]]
    assert first == ["P2", "P4"]


def test_an_alert_that_cannot_be_sent_waits_in_the_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def down(url: str, body: bytes, headers: dict[str, str]) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("zues_scan.server.notify.http_post", down)
    use_scanner(monkeypatch, VSFTPD)

    with caplog.at_level(logging.WARNING, logger="zues_scan.server.notify"):
        summary = scan_target(service_config(tmp_path), "lab", "alice")

    assert summary["code"] == 0 and summary["alerts"] == 1  # the scan is saved anyway
    assert "could not deliver alert #1 (run) to hooks.example.com" in caplog.text
    assert "T0" not in caplog.text  # the webhook's URL is a secret: only its host is logged
    with Storage(tmp_path / "zues.db") as store:
        (row,) = store.alert_rows()
    assert (row["kind"], row["run_id"], row["attempts"], row["sent_at"]) == ("run", 1, 1, None)
    assert "connection refused" in row["last_error"]


def test_without_a_webhook_alerts_are_only_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    use_scanner(monkeypatch, VSFTPD)

    summary = scan_target(service_config(tmp_path, webhook=False), "lab", "alice")

    assert summary["alerts"] == 1 and posted == []
    with Storage(tmp_path / "zues.db") as store:
        assert store.alert_rows() == []  # nothing queued for a webhook that does not exist


def test_a_refused_target_is_reported_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    fake = use_scanner(monkeypatch, VSFTPD)
    config = service_config(tmp_path, target="192.0.2.7")

    summary = scan_target(config, "lab", "alice")
    scan_target(config, "lab", "scheduler")  # the next scheduled try, refused again

    assert summary["code"] == 3 and summary["run_id"] is None and summary["status"] is None
    assert summary["messages"][0].startswith("refused:")
    assert fake.seen == []
    [(_, payload, _)] = posted  # once a day, not at every try
    assert payload["kind"] == "not_started" and payload["target"] == "lab"
    assert payload["text"].startswith("ZuesScan: a scan of lab was not started: refused:")


def failing_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    from zues_scan.plugins.base import ScanError

    error = ScanError("nmap exited with code 1", plugin="fake", stderr="boom")
    monkeypatch.setattr(
        "zues_scan.plugins.registry.NmapPlugin", lambda **_: FakePlugin([], error=error)
    )


def test_one_failed_scan_is_recorded_and_not_alerted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    failing_scanner(monkeypatch)

    summary = scan_target(service_config(tmp_path), "lab", "alice")

    assert summary["code"] == 4 and summary["status"] == "failed" and summary["run_id"] == 1
    assert summary["alerts"] == 0 and posted == []


def test_scans_failing_three_times_in_a_row_alert_once_and_again_when_they_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: Posted
) -> None:
    config = service_config(tmp_path)
    failing_scanner(monkeypatch)
    for _ in range(4):
        scan_target(config, "lab", "scheduler")

    [(_, failed, _)] = posted  # at the third failure, not at every one after it
    assert (failed["kind"], failed["run_id"], failed["failures"]) == ("scan_failed", 3, 3)
    assert failed["text"].startswith("ZuesScan: scans of lab have failed 3 times in a row")
    assert "nmap exited with code 1" in failed["error"]

    use_scanner(monkeypatch, OPENSSH)  # P4: no finding alert
    scan_target(config, "lab", "scheduler")

    recovered = posted[-1][1]
    assert (recovered["kind"], recovered["run_id"], recovered["failures"]) == (
        "scan_recovered",
        5,
        4,
    )
    assert len(posted) == 2


def test_a_job_that_fails_without_a_run_alerts_through_its_callback(
    tmp_path: Path, posted: Posted
) -> None:
    from types import SimpleNamespace

    from zues_scan.server.jobs import job_failed

    config = service_config(tmp_path)
    job = SimpleNamespace(id="j1", args=(config, "lab", "alice"))

    job_failed(job, None, TimeoutError, TimeoutError("Task exceeded maximum timeout"), None)
    job_failed(job, None, TimeoutError, TimeoutError("Task exceeded maximum timeout"), None)

    [(_, payload, _)] = posted  # the same failure again within 6 hours: held back
    assert payload["kind"] == "job_failed" and payload["target"] == "lab"
    assert payload["error"] == "TimeoutError: Task exceeded maximum timeout"


def test_the_failure_callback_never_raises(tmp_path: Path, posted: Posted) -> None:
    from types import SimpleNamespace

    from zues_scan.server.jobs import job_failed

    job = SimpleNamespace(id="j2", args=(str(tmp_path / "missing.toml"), "lab", "alice"))
    job_failed(job, None, RuntimeError, RuntimeError("x"), None)  # its config is gone

    assert posted == []


def test_a_target_removed_from_the_config_fails_the_job(tmp_path: Path) -> None:
    # The job carries a name; the worker re-reads service.toml, so a target taken out
    # after the job was queued is not scanned.
    with pytest.raises(ConfigError, match="no target named 'gone'"):
        scan_target(service_config(tmp_path), "gone", "alice")


def test_a_long_alert_is_cut_at_twenty_lines() -> None:
    items = [
        {"kind": "reappeared", "finding_id": i, "title": f"t{i}", "host": "h"} for i in range(25)
    ]

    payload = notify.message("lab", 7, items)

    lines = payload["text"].splitlines()
    assert len(lines) == 22  # header, 20 items, "and 5 more"
    assert lines[1] == "• REAPPEARED: t0 on h" and lines[-1] == "… and 5 more"
    assert len(payload["items"]) == 25  # the structured part keeps everything
