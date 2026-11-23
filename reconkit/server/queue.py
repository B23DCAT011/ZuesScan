"""The scan queue (Redis + RQ, D6): what the API and the scheduler put work into.

One queue, many workers. A job is "scan configured target X for operator Y", with a
timeout a little longer than the target's profile allows, and a stable description
so that the API can show what is running.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from redis import Redis
from redis import exceptions as redis_errors
from rq import Queue, SimpleWorker, Worker
from rq.job import Job
from rq.timeouts import TimerDeathPenalty

from reconkit.profiles import load_profiles
from reconkit.server.config import ServiceConfig

JOB = "reconkit.server.jobs.scan_target"

# Redis is down or unreachable: the commands say so in one line instead of a traceback.
UNREACHABLE = (redis_errors.ConnectionError, redis_errors.TimeoutError)


def connect(config: ServiceConfig) -> Redis:
    return Redis.from_url(config.redis_url)


def safe_url(url: str) -> str:
    """The Redis URL without its password, for messages and logs."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    host = parts.hostname or ""
    netloc = f"{parts.username or ''}:***@{host}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


def queue(config: ServiceConfig, connection: Redis | None = None) -> Queue:
    return Queue(config.queue, connection=connection or connect(config))


def enqueue_scan(q: Queue, config: ServiceConfig, target_name: str, operator: str) -> Job:
    target = config.target(target_name)
    profile = load_profiles(target.config).get(target.profile)
    timeout = (profile.timeout if profile else 3600) + 600  # the scan's own limit + margin
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
    )


@dataclass(frozen=True, slots=True)
class JobInfo:
    id: str
    target: str | None
    operator: str | None
    status: str
    enqueued_at: str | None
    result: dict[str, Any] | None


def info(job: Job) -> JobInfo:
    status = job.get_status()
    result = job.return_value() if status is not None and str(status.value) == "finished" else None
    return JobInfo(
        id=job.id,
        target=job.meta.get("target"),
        operator=job.meta.get("operator"),
        status=str(status.value) if status is not None else "unknown",
        enqueued_at=job.enqueued_at.isoformat() if job.enqueued_at else None,
        result=result if isinstance(result, dict) else None,
    )


class _WindowsWorker(SimpleWorker):
    """No fork() and no SIGALRM on Windows: run jobs in-process, timed by a thread."""

    death_penalty_class = TimerDeathPenalty


def make_worker(q: Queue) -> Worker | SimpleWorker:
    """A worker for this platform (forking on Unix, in-process on Windows)."""
    if sys.platform == "win32":
        return _WindowsWorker([q], connection=q.connection)
    return Worker([q], connection=q.connection)
