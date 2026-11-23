"""The queue and the scheduler, through real RQ on an in-memory Redis (fakeredis).

Skipped without `reconkit[server,server-test]`. The worker used here runs jobs in
this process (SimpleWorker, timed by a thread), so the test's fake scanner and fake
DNS apply inside the job too — and it is the worker Windows uses for real.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("rq")
fakeredis = pytest.importorskip("fakeredis")

from conftest import FakePlugin, lab_asset, lab_resolver  # noqa: E402
from rq import Queue, SimpleWorker, Worker  # noqa: E402

from reconkit.schema import Service  # noqa: E402
from reconkit.server import queue as rkqueue  # noqa: E402
from reconkit.server import scheduler  # noqa: E402
from reconkit.server.config import (  # noqa: E402
    ConfigError,
    ServiceConfig,
    Target,
    load_config,
    parse_every,
)
from reconkit.storage import Storage  # noqa: E402

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reconkit.scope.resolve_ipv4", lab_resolver)
    monkeypatch.setattr("reconkit.scope.resolve_addresses", lab_resolver)
    fake = FakePlugin([lab_asset(Service(port=22, name="ssh", product="OpenSSH", version="7.4"))])
    monkeypatch.setattr("reconkit.plugins.registry.NmapPlugin", lambda **_: fake)


def write_service(tmp_path: Path) -> ServiceConfig:
    (tmp_path / "scope.txt").write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
    d = tmp_path.as_posix()
    target = f'target = "scanme.lab"\nscope = "{d}/scope.txt"\n'
    (tmp_path / "service.toml").write_text(
        f'[service]\ndb = "{d}/reconkit.db"\nqueue = "test"\n\n'
        f'[[targets]]\nname = "hourly"\n{target}profile = "quick"\nevery = "1h"\n\n'
        f'[[targets]]\nname = "daily"\n{target}profile = "standard"\nevery = "1d"\n\n'
        f'[[targets]]\nname = "manual"\n{target}profile = "full"\n',
        encoding="utf-8",
    )
    return load_config(tmp_path / "service.toml")


@pytest.fixture
def service(tmp_path: Path) -> ServiceConfig:
    return write_service(tmp_path)


@pytest.fixture
def q(service: ServiceConfig) -> Queue:
    return rkqueue.queue(service, connection=fakeredis.FakeRedis())


def work(q: Queue) -> None:
    """Run every queued job in this process, then return."""
    SimpleWorker([q], connection=q.connection).work(burst=True)


# --- the queue ---------------------------------------------------------------------------------


def test_a_queued_scan_carries_names_only(q: Queue, service: ServiceConfig) -> None:
    job = rkqueue.enqueue_scan(q, service, "hourly", "alice")

    assert job.func_name == "reconkit.server.jobs.scan_target"
    assert job.args == (service.path, "hourly", "alice")  # no address, scope or options
    assert job.description == "scan hourly for alice"
    assert job.timeout == 300 + 600  # the quick profile's limit + a margin
    info = rkqueue.info(job)
    assert (info.target, info.operator, info.status) == ("hourly", "alice", "queued")
    assert info.result is None and info.enqueued_at is not None


def test_an_unknown_target_is_never_queued(q: Queue, service: ServiceConfig) -> None:
    with pytest.raises(ConfigError, match="no target named"):
        rkqueue.enqueue_scan(q, service, "10.0.0.9", "alice")
    assert q.count == 0


def test_a_worker_runs_the_scan_and_keeps_its_summary(
    q: Queue, service: ServiceConfig, tmp_path: Path
) -> None:
    job = rkqueue.enqueue_scan(q, service, "hourly", "alice")

    work(q)

    info = rkqueue.info(q.fetch_job(job.id) or job)
    assert info.status == "finished"
    assert info.result is not None
    assert (info.result["code"], info.result["run_id"], info.result["status"]) == (
        0,
        1,
        "completed",
    )
    with Storage(tmp_path / "reconkit.db") as store:
        run = store.load_run(1)
    assert run is not None and run.operator == "alice" and run.profile == "quick"


def test_a_failing_job_is_kept_as_failed(q: Queue, service: ServiceConfig, tmp_path: Path) -> None:
    job = rkqueue.enqueue_scan(q, service, "hourly", "alice")
    # Taken out of the config after it was queued: the worker re-reads it and refuses.
    (tmp_path / "service.toml").write_text(
        f'[service]\ndb = "{tmp_path.as_posix()}/reconkit.db"\n', encoding="utf-8"
    )

    work(q)

    info = rkqueue.info(q.fetch_job(job.id) or job)
    assert info.status == "failed" and info.result is None
    assert not (tmp_path / "reconkit.db").exists()


def test_the_worker_suits_the_platform(q: Queue, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    windows = rkqueue.make_worker(q)
    assert isinstance(windows, SimpleWorker)  # no fork() on Windows
    assert windows.death_penalty_class.__name__ == "TimerDeathPenalty"  # no SIGALRM either

    monkeypatch.setattr(sys, "platform", "linux")
    unix = rkqueue.make_worker(q)
    assert type(unix) is Worker  # a fresh process per job


# --- the scheduler -----------------------------------------------------------------------------


def target(every: str | None) -> Target:
    return Target(
        name="t", target="10.0.0.5", scope="scope.txt", every=parse_every(every) if every else None
    )


@pytest.mark.parametrize(
    ("every", "last_run", "last_enqueued", "expected"),
    [
        (None, None, None, False),  # no schedule: only scanned on request
        ("1h", None, None, True),  # never scanned
        ("1h", NOW - timedelta(minutes=30), None, False),
        ("1h", NOW - timedelta(hours=1), None, True),
        ("1h", NOW - timedelta(hours=3), NOW - timedelta(minutes=5), False),  # still queued
        ("1h", None, NOW - timedelta(hours=2), True),
    ],
)
def test_due(
    every: str | None,
    last_run: datetime | None,
    last_enqueued: datetime | None,
    expected: bool,
) -> None:
    assert scheduler.due(target(every), last_run, last_enqueued, NOW) is expected


def test_a_tick_queues_each_due_target_once(q: Queue, service: ServiceConfig) -> None:
    assert scheduler.tick(service, q, now=NOW) == ["hourly", "daily"]  # not "manual"
    assert scheduler.tick(service, q, now=NOW + timedelta(minutes=1)) == []  # queued already
    assert q.count == 2
    assert {job.meta["operator"] for job in q.jobs} == {"scheduler"}

    assert scheduler.tick(service, q, now=NOW + timedelta(hours=1)) == ["hourly"]
    assert scheduler.tick(service, q, now=NOW + timedelta(days=1)) == ["hourly", "daily"]


def test_the_run_history_is_read_per_profile(q: Queue, service: ServiceConfig) -> None:
    # Only the quick hourly scan of scanme.lab has run; then Redis lost its keys.
    rkqueue.enqueue_scan(q, service, "hourly", "alice")
    work(q)
    q.connection.flushall()

    soon = datetime.now(UTC) + timedelta(minutes=30)
    # The database still says the hourly scan ran recently, but that quick scan must not
    # make the daily standard scan of the same target look done: matched on the profile.
    assert scheduler.tick(service, q, now=soon) == ["daily"]
    assert scheduler.tick(service, q, now=soon + timedelta(hours=1)) == ["hourly"]


def test_a_missing_database_is_not_created(service: ServiceConfig, tmp_path: Path) -> None:
    assert scheduler.last_runs(service.db) == {}
    assert not (tmp_path / "reconkit.db").exists()


def test_a_failing_round_does_not_stop_the_scheduler(
    service: ServiceConfig,
    q: Queue,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    rounds: list[int] = []

    def tick(config: ServiceConfig, queue: Queue) -> list[str]:
        rounds.append(1)
        if len(rounds) == 1:
            raise ConnectionError("redis is restarting")
        return []

    naps: list[float] = []
    monkeypatch.setattr(scheduler, "tick", tick)
    with caplog.at_level(logging.ERROR, logger="reconkit.server.scheduler"):
        scheduler.run_forever(service, q, sleep=naps.append, rounds=3)

    assert len(rounds) == 3
    assert naps == [60.0, 60.0]  # no nap after the last round
    assert "scheduler round failed" in caplog.text


# --- the CLI -----------------------------------------------------------------------------------


@pytest.fixture
def redis(monkeypatch: pytest.MonkeyPatch) -> object:
    """One in-memory Redis for every `reconkit` command of a test."""
    server = fakeredis.FakeRedis()
    monkeypatch.setattr(rkqueue, "connect", lambda config: server)
    return server


def test_cli_enqueue_then_worker_then_scheduler(
    service: ServiceConfig,
    tmp_path: Path,
    redis: object,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from reconkit import cli

    # The CLI's worker is the platform's; the in-process one keeps the fakes in effect.
    monkeypatch.setattr(
        rkqueue, "make_worker", lambda q: SimpleWorker([q], connection=q.connection)
    )
    config = service.path

    assert cli.main(["enqueue", "manual", "--config", config, "--operator", "alice"]) == 0
    assert "scan of manual enqueued as job " in capsys.readouterr().out

    assert cli.main(["worker", "--config", config, "--burst"]) == 0
    with Storage(tmp_path / "reconkit.db") as store:
        [summary] = store.list_runs()
        run = store.load_run(summary.id)
    assert run is not None and run.operator == "alice"

    assert cli.main(["scheduler", "--config", config, "--once"]) == 0
    assert capsys.readouterr().out == "enqueued: hourly, daily\n"
    assert cli.main(["scheduler", "--config", config, "--once"]) == 0
    assert capsys.readouterr().out == "enqueued: nothing due\n"


def test_cli_refuses_an_unknown_target_or_a_bad_config(
    service: ServiceConfig, tmp_path: Path, redis: object, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit import cli

    assert cli.main(["enqueue", "10.0.0.9", "--config", service.path]) == 1
    assert "no target named '10.0.0.9'" in capsys.readouterr().err

    bad = tmp_path / "bad.toml"
    bad.write_text("[service]\n", encoding="utf-8")
    assert cli.main(["worker", "--config", str(bad)]) == 2
    assert "needs db" in capsys.readouterr().err


def test_an_unreachable_redis_is_one_line_without_the_password(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit import cli

    d = tmp_path.as_posix()
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    (tmp_path / "service.toml").write_text(
        # Port 1: nothing listens there; the password must not reach the terminal or logs.
        f'[service]\ndb = "{d}/reconkit.db"\nredis_url = "redis://:s3cret@127.0.0.1:1/0"\n'
        f'[[targets]]\nname = "x"\ntarget = "10.0.0.5"\nscope = "{d}/scope.txt"\nevery = "1h"\n',
        encoding="utf-8",
    )
    config = str(tmp_path / "service.toml")

    for command in (["scheduler", "--once"], ["worker", "--burst"], ["enqueue", "x"]):
        assert cli.main([*command, "--config", config]) == 1, command
        err = capsys.readouterr().err
        assert err.startswith("error: cannot reach Redis at redis://:***@127.0.0.1:1/0: "), err
        assert "s3cret" not in err and "Traceback" not in err


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("redis://localhost:6379/0", "redis://localhost:6379/0"),
        ("redis://:pw@redis:6379/0", "redis://:***@redis:6379/0"),
        ("rediss://user:pw@cache.example.com/1", "rediss://user:***@cache.example.com/1"),
    ],
)
def test_safe_url_hides_the_password(url: str, shown: str) -> None:
    assert rkqueue.safe_url(url) == shown


def test_two_schedulers_never_run_a_round_at_once(q: Queue, service: ServiceConfig) -> None:
    # Another scheduler holds the round's lock: this one must not enqueue anything.
    q.connection.set("reconkit:scheduler:lock:test", "someone-else", ex=30)
    assert scheduler.tick(service, q, now=NOW) == []
    assert q.count == 0
    assert q.connection.get("reconkit:scheduler:lock:test") == b"someone-else"  # not ours

    q.connection.delete("reconkit:scheduler:lock:test")
    assert scheduler.tick(service, q, now=NOW) == ["hourly", "daily"]
    assert q.connection.get("reconkit:scheduler:lock:test") is None  # freed after the round
