"""Scan limits (G26): one scan of a target at a time, and a number of scan requests an hour
per token — so that an agent, a script or a leaked token cannot keep a target under scan.

Through the web API on an in-memory Redis; the worker runs jobs in this process.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
fakeredis = pytest.importorskip("fakeredis")

from conftest import FakePlugin, lab_asset  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from test_server_web import ALICE, TOKENS, VSFTPD, App, _lab, config_text, sha  # noqa: E402,F401

from zues_scan.cli import main  # noqa: E402
from zues_scan.plugins.base import ScanResult  # noqa: E402
from zues_scan.schema import ScanTarget  # noqa: E402
from zues_scan.server import queue as rkqueue  # noqa: E402
from zues_scan.server.config import ConfigError, load_config  # noqa: E402
from zues_scan.storage import Storage  # noqa: E402

ROOT = "root-admin-token-0123456789abcdefghijklmnopq"
AGENT = "agent-operator-token-0123456789abcdefghijkl"


def tokens(agent: str = "scans_per_hour = 2\n") -> str:
    return (
        TOKENS
        + f'[[tokens]]\nname = "root"\nsha256 = "{sha(ROOT)}"\nrole = "admin"\n\n'
        + f'[[tokens]]\nname = "agent"\nsha256 = "{sha(AGENT)}"\nrole = "operator"\n{agent}\n'
    )


@pytest.fixture
def svc(tmp_path: Path) -> App:
    app = App(tmp_path)
    app.rewrite(config_text(tmp_path.as_posix(), tokens()))
    return app


def scan(client: TestClient, target: str) -> Any:
    return client.post("/api/v1/scans", json={"target": target})


# --- one scan of a target at a time -------------------------------------------------------------


def test_a_target_waiting_for_its_scan_is_not_queued_again(svc: App) -> None:
    alice = svc.client(ALICE)
    first = scan(alice, "lab")
    assert first.status_code == 202
    again = scan(svc.client(ROOT), "lab")  # anyone: it is about the target, not the token
    assert again.status_code == 409
    job = first.json()["job"]["id"]
    assert again.json()["detail"] == f"a scan of lab is already queued (job {job})"
    assert scan(alice, "dmz").status_code == 202  # another target is another matter

    svc.work()
    assert scan(alice, "lab").status_code == 202  # done: it may be scanned again


def test_a_running_scan_counts_too(svc: App, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    class Slow(FakePlugin):
        def scan(self, target: ScanTarget) -> ScanResult:
            seen.append(scan(svc.client(ALICE), "lab"))  # asked while the worker scans
            return super().scan(target)

    slow = Slow([lab_asset(VSFTPD)])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: slow)
    assert scan(svc.client(ALICE), "lab").status_code == 202
    svc.work()

    (during,) = seen
    assert during.status_code == 409 and "is already running" in during.json()["detail"]
    with Storage(svc.db) as store:
        assert len(store.list_runs()) == 1


def test_requests_at_the_same_moment_queue_one_scan(svc: App) -> None:
    q = rkqueue.queue(load_config(svc.config), connection=svc.redis)
    config = load_config(svc.config)
    start = threading.Barrier(8)
    outcomes: list[str] = []

    def request(n: int) -> None:
        start.wait()
        try:
            rkqueue.enqueue_scan(q, config, "lab", f"op{n}")
            outcomes.append("queued")
        except rkqueue.AlreadyQueued:
            outcomes.append("refused")

    threads = [threading.Thread(target=request, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["queued"] + ["refused"] * 7
    assert q.count == 1
    assert svc.redis.keys("zues:enqueue:*") == []  # the lock is freed


def test_the_command_line_refuses_a_second_scan_too(
    svc: App, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rkqueue, "connect", lambda config: svc.redis)
    command = ["enqueue", "lab", "--config", str(svc.config)]
    assert main(command) == 0
    assert main(command) == 1
    assert "a scan of lab is already queued" in capsys.readouterr().err


# --- scan requests an hour, per token -----------------------------------------------------------


def test_a_token_over_its_limit_is_told_when_to_ask_again(svc: App) -> None:
    agent = svc.client(AGENT)
    assert scan(agent, "lab").status_code == 202
    assert scan(agent, "lab").status_code == 409  # refused as a duplicate: not counted
    assert scan(agent, "dmz").status_code == 202  # the second of 2
    svc.work()

    over = scan(agent, "lab")
    assert over.status_code == 429
    assert over.json()["detail"] == "agent may request 2 scan(s) an hour: the next one in 60 min"
    assert 3590 <= int(over.headers["Retry-After"]) <= 3600
    assert scan(svc.client(ALICE), "lab").status_code == 202  # another token: no limit


def test_the_hour_slides() -> None:
    redis = fakeredis.FakeRedis()
    assert rkqueue.take_scan(redis, "agent", 2, now=1000.0) == 0
    assert rkqueue.take_scan(redis, "agent", 2, now=2000.0) == 0
    assert rkqueue.take_scan(redis, "agent", 2, now=2800.0) == 1800  # until 1000's hour ends
    assert rkqueue.take_scan(redis, "agent", 2, now=4600.0) == 0  # 1000 is an hour ago
    assert rkqueue.take_scan(redis, "agent", 2, now=4700.0) == 900  # 2000 and 4600 count
    assert rkqueue.take_scan(redis, "other", 2, now=4700.0) == 0  # per token
    assert redis.ttl("zues:scans:agent") > 3600  # the key goes away by itself


def test_scheduled_scans_do_not_count(svc: App) -> None:
    from zues_scan.server import scheduler

    q = rkqueue.queue(load_config(svc.config), connection=svc.redis)
    assert scheduler.tick(load_config(svc.config), q) == ["lab"]  # the hourly target
    assert scan(svc.client(AGENT), "dmz").status_code == 202
    assert scan(svc.client(AGENT), "lab").status_code == 409  # the scheduler's scan waits
    svc.work()
    assert scan(svc.client(AGENT), "lab").status_code == 202  # its 2nd: the 1st was dmz


# --- setting the limit ---------------------------------------------------------------------------


def test_an_admin_sets_a_limit_that_applies_at_once(svc: App) -> None:
    root = svc.client(ROOT)
    made = root.post(
        "/api/v1/admin/tokens", json={"name": "bot", "role": "operator", "scans_per_hour": 1}
    )
    assert made.status_code == 201, made.text
    bot = svc.client(made.json()["token"])
    assert scan(bot, "lab").status_code == 202
    svc.work()
    assert scan(bot, "lab").status_code == 429

    assert root.put("/api/v1/admin/tokens/bot/quota", json={"scans_per_hour": None}).json() == {
        "name": "bot",
        "scans_per_hour": None,
    }
    assert scan(bot, "lab").status_code == 202  # no limit any more
    root.put("/api/v1/admin/tokens/bot/quota", json={"scans_per_hour": 5})

    listed = {t["name"]: t for t in root.get("/api/v1/admin/config").json()["tokens"]}
    assert (listed["bot"]["scans_per_hour"], listed["agent"]["scans_per_hour"]) == (5, 2)
    assert listed["alice"]["scans_per_hour"] is None
    with Storage(svc.db) as store:
        details = [e.detail for _, e, _ in store.audit_events() if e.target == "token:bot"]
    assert details[0]["scans_per_hour"] == 1
    assert [d["scans_per_hour"] for d in details if d["action"] == "token scan limit changed"] == [
        None,
        5,
    ]


def test_wrong_limits_are_refused(svc: App) -> None:
    root = svc.client(ROOT)
    viewer = {"name": "v", "role": "viewer", "scans_per_hour": 3}
    refused = root.post("/api/v1/admin/tokens", json=viewer)
    assert refused.status_code == 422 and "a viewer cannot request scans" in refused.text
    for wrong in (0, 1001, "many"):
        body = {"name": "x", "role": "operator", "scans_per_hour": wrong}
        assert root.post("/api/v1/admin/tokens", json=body).status_code == 422
        put = root.put("/api/v1/admin/tokens/agent/quota", json={"scans_per_hour": wrong})
        assert put.status_code == 422
    # A service.toml token is changed in service.toml, not in the dashboard.
    file_token = root.put("/api/v1/admin/tokens/agent/quota", json={"scans_per_hour": 4})
    assert file_token.status_code == 404
    assert root.put("/api/v1/admin/tokens/agent/quota", json={}).status_code == 422
    assert (
        svc.client(ALICE)
        .put("/api/v1/admin/tokens/agent/quota", json={"scans_per_hour": 9})
        .status_code
        == 403
    )


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("scans_per_hour = 0\n", "from 1 to 1000"),
        ("scans_per_hour = 1001\n", "from 1 to 1000"),
        ('scans_per_hour = "6"\n', "from 1 to 1000"),
        ("scans_per_hour = true\n", "from 1 to 1000"),
    ],
)
def test_the_service_file_is_checked(tmp_path: Path, line: str, message: str) -> None:
    path = tmp_path / "service.toml"
    path.write_text(config_text(tmp_path.as_posix(), tokens(line)), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_a_viewer_in_the_service_file_has_no_limit(tmp_path: Path) -> None:
    text = config_text(tmp_path.as_posix(), tokens("scans_per_hour = 3\n"))
    text = text.replace('role = "operator"\nscans_per_hour', 'role = "viewer"\nscans_per_hour')
    path = tmp_path / "service.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="a viewer cannot request scans"):
        load_config(path)


def test_zues_user_sets_the_limit(svc: App, capsys: pytest.CaptureFixture[str]) -> None:
    user = ["user", "--config", str(svc.config)]
    assert main([*user, "add", "ci", "--role", "operator", "--scans-per-hour", "4"]) == 0
    assert main([*user, "list"]) == 0
    listed = capsys.readouterr().out
    assert "SCANS/H" in listed
    (ci,) = [line for line in listed.splitlines() if line.startswith("ci ")]
    assert ci.split()[-2:] == ["4", "all"]
    (agent,) = [line for line in listed.splitlines() if line.startswith("agent ")]
    assert agent.split()[-2:] == ["2", "all"]

    assert main([*user, "quota", "ci", "none"]) == 0
    assert capsys.readouterr().out == "ci: no limit\n"
    (made,) = [t for t in load_config(svc.config).tokens if t.name == "ci"]
    assert made.scans_per_hour is None
    assert main([*user, "quota", "ci", "12"]) == 0
    assert "ci: 12 scan request(s) an hour" in capsys.readouterr().out

    assert main([*user, "quota", "ci", "0"]) == 2
    assert "from 1 to 1000" in capsys.readouterr().err
    assert main([*user, "add", "eve", "--role", "viewer", "--scans-per-hour", "3"]) == 2
    assert main([*user, "quota", "agent", "3"]) == 2  # a service.toml token
    with pytest.raises(SystemExit):
        main([*user, "quota", "ci", "lots"])
