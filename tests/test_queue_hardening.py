"""Writing to Redis is not running code in a worker (G25, D19): jobs are JSON, a worker
runs only ZuesScan's scan job, and Redis's password comes from a file a plugin's process
cannot read. Before, a plugin in the worker's container could queue any call on an open
Redis and have it run outside its sandbox (checked for real)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("rq")
fakeredis = pytest.importorskip("fakeredis")

from rq import Callback, Queue  # noqa: E402
from test_server_queue import work, write_service  # noqa: E402

from zues_scan.plugins import process  # noqa: E402
from zues_scan.server import queue as rkqueue  # noqa: E402
from zues_scan.server.config import ConfigError, ServiceConfig, from_environment  # noqa: E402


@pytest.fixture
def q(tmp_path: Path) -> Queue:
    return rkqueue.queue(write_service(tmp_path), connection=fakeredis.FakeRedis())


def refused(q: Queue, job_id: str) -> str:
    job = q.fetch_job(job_id)
    assert job is not None
    info = rkqueue.info(job)
    assert info.status == "failed"
    return info.error or ""


def test_a_job_that_is_not_zuesscans_is_failed_unrun(q: Queue, tmp_path: Path) -> None:
    planted = tmp_path / "planted"
    job = q.enqueue("os.mkdir", str(planted))  # what an attacker on Redis would queue
    work(q)
    assert not planted.exists()
    assert refused(q, job.id) == "RefusedJob: it calls 'os.mkdir', not ZuesScan's scan job"


def test_a_pickled_job_is_never_unpickled(q: Queue, tmp_path: Path) -> None:
    planted = tmp_path / "planted"
    pickled = Queue(q.name, connection=q.connection)  # RQ's default serializer: pickle
    job = pickled.enqueue("os.mkdir", str(planted))
    work(q)
    assert not planted.exists()
    assert "cannot be read as JSON" in refused(q, job.id)


def test_a_foreign_callback_is_refused_too(q: Queue, tmp_path: Path) -> None:
    job = q.enqueue(rkqueue.JOB, "x", "y", "z", on_success=Callback("os.getcwd"))
    work(q)
    assert "its callbacks are not ZuesScan's: os.getcwd" in refused(q, job.id)


def test_zuesscans_own_job_still_runs(q: Queue) -> None:
    job = q.enqueue(rkqueue.JOB, "/nowhere/service.toml", "lan", "alice")
    assert rkqueue.refusal(job) is None
    job = q.enqueue(
        rkqueue.JOB, "/nowhere/service.toml", "lan", "a", on_failure=Callback(rkqueue.JOB_FAILED)
    )
    assert rkqueue.refusal(job) is None


# --- Redis's password -------------------------------------------------------------------------


def config(tmp_path: Path, **changes: str) -> ServiceConfig:
    return ServiceConfig(path="x", db=str(tmp_path / "zues.db"), **changes)  # type: ignore[arg-type]


def test_the_password_comes_from_its_file(tmp_path: Path) -> None:
    secret = tmp_path / "redis.pass"
    secret.write_text("  s3cret-of-redis\n", encoding="utf-8")
    service = config(tmp_path, redis_password_file=str(secret))
    assert rkqueue.redis_password(service) == "s3cret-of-redis"
    redis = rkqueue.connect(service)
    assert redis.connection_pool.connection_kwargs["password"] == "s3cret-of-redis"
    assert rkqueue.has_password(service)
    assert rkqueue.redis_password(config(tmp_path)) is None
    assert not rkqueue.has_password(config(tmp_path))
    assert rkqueue.has_password(config(tmp_path, redis_url="redis://:pw@redis:6379/0"))


@pytest.mark.parametrize(
    ("content", "url", "error"),
    [
        (None, "redis://redis:6379/0", "cannot read the Redis password file"),
        ("  \n", "redis://redis:6379/0", "is empty"),
        ("pw", "redis://:pw@redis:6379/0", "in redis_url and in redis_password_file"),
    ],
)
def test_a_password_file_that_cannot_serve(
    tmp_path: Path, content: str | None, url: str, error: str
) -> None:
    secret = tmp_path / "redis.pass"
    if content is not None:
        secret.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=error):
        rkqueue.connect(config(tmp_path, redis_password_file=str(secret), redis_url=url))


def test_where_the_service_reads_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "zues.db"))
    monkeypatch.setenv("ZUES_REDIS_PASSWORD_FILE", "/secrets/redis.pass")
    assert from_environment().redis_password_file == "/secrets/redis.pass"
    service = write_service(tmp_path)
    assert service.redis_password_file == "/secrets/redis.pass"  # unset in it: compose's
    monkeypatch.delenv("ZUES_REDIS_PASSWORD_FILE")
    assert write_service(tmp_path).redis_password_file is None
    toml = Path(service.path)
    toml.write_text(
        toml.read_text(encoding="utf-8").replace(
            "[service]\n", '[service]\nredis_password_file = "/run/own.pass"\n'
        ),
        encoding="utf-8",
    )
    from zues_scan.server.config import load_config

    monkeypatch.setenv("ZUES_REDIS_PASSWORD_FILE", "/secrets/redis.pass")
    assert load_config(toml).redis_password_file == "/run/own.pass"  # the file's wins


def test_a_plugins_process_cannot_read_it() -> None:
    """Landlock's allow list (D16) holds nothing above compose's /secrets/redis.pass."""
    ref = process.Ref("probe", "probe_plugin:Probe")
    secret = "/secrets/redis.pass"
    assert not [p for p in process.readable(ref, {}) if secret.startswith(p.rstrip("/") + "/")]
    assert "ZUES_REDIS_PASSWORD_FILE" not in process._PASSED_ENV
