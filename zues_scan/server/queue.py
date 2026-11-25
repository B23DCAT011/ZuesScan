"""The scan queue (Redis + RQ, D6): what the API and the scheduler put work into.

One queue, many workers. A job is "scan configured target X for operator Y", with a
timeout a little longer than the target's profile allows, and a stable description
so that the API can show what is running.

Whoever can write to Redis must not be able to run code in a worker (D19). RQ's default
is pickle: a job is a pickled call, and a worker runs whatever function it names - a
third-party plugin, which runs inside the worker's container with the worker's network,
could reach an open Redis, queue `subprocess.getoutput(...)` and have it run *outside*
its sandbox (checked for real). So:

* jobs are JSON (`JSONSerializer`): reading one never runs code;
* a worker runs only ZuesScan's own job (`JOB`, and `JOB_FAILED` as its failure
  callback); any other job is failed unrun, and the worker log says so;
* Redis can have a password, read from a file (`redis_password_file` /
  `ZUES_REDIS_PASSWORD_FILE`; compose generates one): a plugin's process gets no
  `ZUES_*` variable, and Landlock keeps it from reading the file (D15, D16).

Jobs queued by an older version (pickled) are refused the same way: drain the queue
before upgrading.
"""

from __future__ import annotations

import math
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redis import Redis
from redis import exceptions as redis_errors
from rq import Callback, Queue, SimpleWorker, Worker
from rq.exceptions import DeserializationError
from rq.job import Job
from rq.serializers import JSONSerializer
from rq.timeouts import TimerDeathPenalty

from zues_scan.profiles import load_profiles
from zues_scan.server.config import ConfigError, ServiceConfig

JOB = "zues_scan.server.jobs.scan_target"
JOB_FAILED = "zues_scan.server.jobs.job_failed"  # alerts when a job fails without a run

# Redis is down or unreachable: the commands say so in one line instead of a traceback.
UNREACHABLE = (redis_errors.ConnectionError, redis_errors.TimeoutError)


SERIALIZER = JSONSerializer


def connect(config: ServiceConfig) -> Redis:
    password = redis_password(config)
    if password is None:
        return Redis.from_url(config.redis_url)
    return Redis.from_url(config.redis_url, password=password)


def redis_password(config: ServiceConfig) -> str | None:
    """The password in `redis_password_file`, read now (a new one is used at the next
    connection); None without a file."""
    if not config.redis_password_file:
        return None
    if urlsplit(config.redis_url).password is not None:
        raise ConfigError("Redis's password is in redis_url and in redis_password_file: keep one")
    path = Path(config.redis_password_file)
    try:
        password = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"cannot read the Redis password file {path}: {exc.strerror}") from None
    if not password:
        raise ConfigError(f"the Redis password file {path} is empty")
    return password


def has_password(config: ServiceConfig) -> bool:
    return bool(config.redis_password_file) or urlsplit(config.redis_url).password is not None


def safe_url(url: str) -> str:
    """The Redis URL without its password, for messages and logs."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    host = parts.hostname or ""
    netloc = f"{parts.username or ''}:***@{host}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


def queue(config: ServiceConfig, connection: Redis | None = None) -> Queue:
    return Queue(config.queue, connection=connection or connect(config), serializer=SERIALIZER)


def refusal(job: Job) -> str | None:
    """Why a worker must not run `job` (not ZuesScan's scan job), or None."""
    try:
        name, instance = job.func_name, job.instance
    except DeserializationError:
        return "its call cannot be read as JSON (queued by an older version, or not by ZuesScan)"
    if instance is not None or name != JOB:
        return f"it calls {str(name)[:100]!r}, not ZuesScan's scan job"
    callbacks = {
        job._success_callback_name,
        job._failure_callback_name,
        job._stopped_callback_name,
    } - {None}
    if callbacks - {JOB_FAILED}:
        return f"its callbacks are not ZuesScan's: {', '.join(sorted(map(str, callbacks)))[:200]}"
    return None


class _Guarded:
    """A worker that fails, unrun, any job that is not ZuesScan's (see `refusal`)."""

    def execute_job(self, job: Job, queue: Queue) -> None:
        problem = refusal(job)
        if problem is None:
            super().execute_job(job, queue)  # type: ignore[misc]
            return
        worker: Any = self
        worker.log.warning("refused job %s: %s", job.id, problem)
        # No failure callback either: its name is part of what was refused.
        job._failure_callback_name = None
        worker.handle_job_failure(job, queue, exc_string=f"RefusedJob: {problem}")


class AlreadyQueued(Exception):
    """A scan of that target waits or runs already: a second one would only double the
    load on the target (and, scheduled, pile up behind a scan longer than its interval)."""

    def __init__(self, target: str, job: Job, status: str) -> None:
        super().__init__(f"a scan of {target} is already {status} (job {job.id})")
        self.job = job


_ACTIVE = ("queued", "started", "deferred", "scheduled")


def active_scan(q: Queue, target_name: str) -> tuple[Job, str] | None:
    """The job (and its status) of a scan of `target_name` that waits or runs, if any."""
    ids = [*q.get_job_ids(), *q.started_job_registry.get_job_ids()]
    for job in Job.fetch_many(ids, connection=q.connection, serializer=SERIALIZER):
        if job is None or (job.meta or {}).get("target") != target_name:
            continue
        status = job.get_status()
        state = str(status.value) if status is not None else ""
        if state in _ACTIVE:
            return job, "running" if state == "started" else "queued"
    return None


HOUR = 3600
_QUOTA_KEY = "zues:scans:{name}"


def take_scan(redis: Any, name: str, per_hour: int, now: float | None = None) -> int:
    """Count one scan request of the token `name` if it has one left in the last hour;
    0 then. Otherwise count nothing and return the seconds until it has one. The count
    is a sorted set of request times, updated in one transaction (WATCH); a request
    counts for one hour: from its time, up to (not including) an hour later."""
    at = time.time() if now is None else now
    key = _QUOTA_KEY.format(name=name)

    def attempt(pipe: Any) -> int:
        recent = sorted(
            float(s) for _, s in pipe.zrangebyscore(key, f"({at - HOUR}", "+inf", withscores=True)
        )
        if len(recent) >= per_hour:
            return max(1, math.ceil(recent[len(recent) - per_hour] + HOUR - at))
        pipe.multi()
        pipe.zremrangebyscore(key, "-inf", at - HOUR)
        pipe.zadd(key, {f"{at:.6f}-{uuid.uuid4().hex[:8]}": at})
        pipe.expire(key, HOUR + 60)
        return 0

    wait: int = redis.transaction(attempt, key, value_from_callable=True)
    return wait


_TARGET_LOCK = "zues:enqueue:{queue}:{target}"
_LOCK_SECONDS = 10


@contextmanager
def _target_lock(q: Queue, target_name: str) -> Iterator[None]:
    """Hold the target's short lock: two requests at once (dashboard, MCP, scheduler)
    cannot both see "no scan yet" and both queue one. Waits up to its life for it."""
    redis: Any = q.connection
    key = _TARGET_LOCK.format(queue=q.name, target=target_name)
    holder = uuid.uuid4().hex
    deadline = time.monotonic() + _LOCK_SECONDS
    while not redis.set(key, holder, nx=True, ex=_LOCK_SECONDS):
        if time.monotonic() > deadline:
            raise TimeoutError(f"another request holds the queue of {target_name}; try again")
        time.sleep(0.05)
    try:
        yield
    finally:
        held = redis.get(key)
        if (held.decode() if isinstance(held, bytes) else held) == holder:  # not another's
            redis.delete(key)


def enqueue_scan(q: Queue, config: ServiceConfig, target_name: str, operator: str) -> Job:
    """Queue a scan of a configured target; AlreadyQueued if one waits or runs."""
    target = config.target(target_name)
    profile = load_profiles(target.config).get(target.profile)
    timeout = (profile.timeout if profile else 3600) + 600  # the scan's own limit + margin
    with _target_lock(q, target_name):
        active = active_scan(q, target_name)
        if active is not None:
            raise AlreadyQueued(target_name, *active)
        return _enqueue(q, config, target_name, operator, timeout)


def _enqueue(q: Queue, config: ServiceConfig, target_name: str, operator: str, timeout: int) -> Job:
    return q.enqueue(
        JOB,
        config.path,
        target_name,
        operator,
        job_timeout=timeout,
        result_ttl=7 * 86400,
        failure_ttl=30 * 86400,
        description=f"scan {target_name} for {operator}",
        meta={"target": target_name, "operator": operator},
        on_failure=Callback(JOB_FAILED),
    )


@dataclass(frozen=True, slots=True)
class JobInfo:
    id: str
    target: str | None
    operator: str | None
    status: str
    enqueued_at: str | None
    started_at: str | None
    ended_at: str | None
    result: dict[str, Any] | None  # the job's summary (jobs.scan_target), once finished
    error: str | None  # the last line of the exception, if the job failed

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__slots__}


def info(job: Job) -> JobInfo:
    status = job.get_status()
    state = str(status.value) if status is not None else "unknown"
    result = job.return_value() if state == "finished" else None
    error = None
    if state == "failed":
        latest = job.latest_result()
        text = (latest.exc_string if latest is not None else None) or ""
        # The last line ("ConfigError: no target named ...") says what went wrong; the
        # traceback, with the server's paths, stays in the worker's log.
        error = text.strip().splitlines()[-1] if text.strip() else "failed"
    return JobInfo(
        id=job.id,
        target=job.meta.get("target"),
        operator=job.meta.get("operator"),
        status=state,
        enqueued_at=_iso(job.enqueued_at),
        started_at=_iso(job.started_at),
        ended_at=_iso(job.ended_at),
        result=result if isinstance(result, dict) else None,
        error=error,
    )


def recent_jobs(q: Queue, limit: int = 50) -> list[JobInfo]:
    """Queued, running, finished and failed jobs of the queue, newest first."""
    ids = list(q.get_job_ids())
    for registry in (
        q.started_job_registry,
        q.finished_job_registry,
        q.failed_job_registry,
    ):
        ids.extend(registry.get_job_ids(desc=True, end=limit - 1))
    jobs = [
        j
        for j in Job.fetch_many(dict.fromkeys(ids), connection=q.connection, serializer=SERIALIZER)
        if j
    ]
    infos = [info(j) for j in jobs]
    infos.sort(key=lambda i: i.enqueued_at or "", reverse=True)
    return infos[:limit]


def _iso(moment: Any) -> str | None:
    return None if moment is None else str(moment.isoformat())


class _Worker(_Guarded, Worker):
    """Forks a work horse per job (Unix)."""


class _WindowsWorker(_Guarded, SimpleWorker):
    """No fork() and no SIGALRM on Windows: run jobs in-process, timed by a thread."""

    death_penalty_class = TimerDeathPenalty


def make_worker(q: Queue, fork: bool | None = None) -> Worker | SimpleWorker:
    """A worker for this platform (forking on Unix, in-process on Windows; `fork` to
    choose) that runs only ZuesScan's jobs, read as JSON."""
    if fork is None:
        fork = sys.platform != "win32"
    kind = _Worker if fork else _WindowsWorker
    return kind([q], connection=q.connection, serializer=SERIALIZER)
