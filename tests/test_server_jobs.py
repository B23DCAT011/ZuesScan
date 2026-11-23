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


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Every webhook delivery, decoded, instead of a real HTTP POST."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def record(url: str, body: bytes) -> None:
        calls.append((url, json.loads(body)))

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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
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
    [(url, payload)] = posted
    assert url == "https://hooks.example.com/T0"
    assert payload["target"] == "lab" and payload["run_id"] == 1
    assert payload["text"].splitlines() == [
        "ZuesScan: run #1 of lab needs attention",
        "• NEW P2: vsftpd 2.3.4 backdoor command execution on scanme.lab (CVSS 9.8)",
    ]
    [item] = payload["items"]
    assert (item["kind"], item["cve"], item["priority"]) == ("new", "CVE-2011-2523", "P2")


def test_nothing_new_means_no_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
) -> None:
    use_scanner(monkeypatch, VSFTPD)
    config = service_config(tmp_path)

    scan_target(config, "lab", "alice")
    second = scan_target(config, "lab", "alice")

    assert second["code"] == 0 and second["alerts"] == 0
    assert len(posted) == 1  # only the first run's


def test_a_fake_fix_is_alerted_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
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


def test_a_lost_alert_does_not_fail_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def down(url: str, body: bytes) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("zues_scan.server.notify.http_post", down)
    use_scanner(monkeypatch, VSFTPD)

    with caplog.at_level(logging.WARNING, logger="zues_scan.server.notify"):
        summary = scan_target(service_config(tmp_path), "lab", "alice")

    assert summary["code"] == 0 and summary["alerts"] == 1  # the scan is saved anyway
    assert "could not deliver the alert" in caplog.text


def test_without_a_webhook_alerts_are_only_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
) -> None:
    use_scanner(monkeypatch, VSFTPD)

    summary = scan_target(service_config(tmp_path, webhook=False), "lab", "alice")

    assert summary["alerts"] == 1 and posted == []


def test_a_refused_target_is_reported_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
) -> None:
    fake = use_scanner(monkeypatch, VSFTPD)

    summary = scan_target(service_config(tmp_path, target="192.0.2.7"), "lab", "alice")

    assert summary["code"] == 3 and summary["run_id"] is None and summary["status"] is None
    assert summary["messages"][0].startswith("refused:")
    assert fake.seen == [] and posted == []


def test_a_failed_scan_is_recorded_and_not_alerted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posted: list[tuple[str, dict[str, Any]]]
) -> None:
    from zues_scan.plugins.base import ScanError

    error = ScanError("nmap exited with code 1", plugin="fake", stderr="boom")
    monkeypatch.setattr(
        "zues_scan.plugins.registry.NmapPlugin", lambda **_: FakePlugin([], error=error)
    )

    summary = scan_target(service_config(tmp_path), "lab", "alice")

    assert summary["code"] == 4 and summary["status"] == "failed" and summary["run_id"] == 1
    assert summary["alerts"] == 0 and posted == []


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


def test_send_reports_delivery() -> None:
    seen: list[bytes] = []

    def ok(url: str, body: bytes) -> None:
        seen.append(body)

    def refused(url: str, body: bytes) -> None:
        raise ConnectionError("refused")

    assert notify.send("https://h/x", {"text": "Lỗ hổng"}, post=ok) is True
    assert json.loads(seen[0]) == {"text": "Lỗ hổng"}  # UTF-8, not \\u escapes
    assert "Lỗ hổng".encode() in seen[0]
    assert notify.send("https://h/x", {"text": "x"}, post=refused) is False
