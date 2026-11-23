"""Scheduled scans: enqueue each target with `every = ...` when it is due.

A target is due when neither its last stored run nor its last enqueued job is more
recent than `every`. The time of the last enqueue is kept in Redis, so that a
scheduler restart, or two schedulers by mistake, do not enqueue the same scan twice
while it waits in the queue. Stored runs are matched on target *and* profile: a
quick hourly scan of a network must not make its daily full scan look done.

`due()` is a pure function; `tick()` does one round; `run_forever()` loops.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from redis import Redis
from rq import Queue

from zues_scan.server.config import ServiceConfig, Target
from zues_scan.server.queue import enqueue_scan
from zues_scan.storage import Storage, StorageError

log = logging.getLogger(__name__)

OPERATOR = "scheduler"
_KEY = "zues:scheduler:last:{name}"
_LOCK = "zues:scheduler:lock:{queue}"
_LOCK_SECONDS = 30  # far longer than a round takes; freed at its end anyway


def due(
    target: Target, last_run: datetime | None, last_enqueued: datetime | None, now: datetime
) -> bool:
    if target.every is None:
        return False
    latest = max((t for t in (last_run, last_enqueued) if t is not None), default=None)
    return latest is None or now - latest >= target.every


def last_runs(db: str) -> dict[tuple[str, str | None], datetime]:
    """Start time of the newest stored run of each (target, profile)."""
    if not Path(db).is_file():
        return {}  # nothing ran yet; and the scheduler must not create the database
    try:
        with Storage(db) as store:
            starts = store.latest_starts()
    except StorageError as exc:
        # Keep scheduling from Redis alone; the worker will report the database error.
        log.warning("cannot read the run history in %s: %s", db, exc)
        return {}
    return {key: datetime.fromisoformat(at) for key, at in starts.items()}


def tick(config: ServiceConfig, q: Queue, now: datetime | None = None) -> list[str]:
    """Enqueue every due target once; return their names.

    One round at a time across all schedulers: a round holds a short Redis lock, so
    that two schedulers started by mistake cannot both read "not queued yet" and both
    enqueue the same scan. A round that finds the lock taken does nothing.
    """
    now = now or datetime.now(UTC)
    redis: Redis = q.connection
    lock = _LOCK.format(queue=config.queue)
    holder = uuid.uuid4().hex
    if not redis.set(lock, holder, nx=True, ex=_LOCK_SECONDS):
        log.info("another scheduler is running a round; skipping this one")
        return []
    try:
        return _enqueue_due(config, q, redis, now)
    finally:
        if _text(redis.get(lock)) == holder:  # never free a lock that expired into another's
            redis.delete(lock)


def _enqueue_due(config: ServiceConfig, q: Queue, redis: Redis, now: datetime) -> list[str]:
    history = last_runs(config.db)
    enqueued = []
    for target in config.targets.values():
        key = _KEY.format(name=target.name)
        text = _text(redis.get(key))
        last_enqueued = datetime.fromisoformat(text) if text else None
        last_run = history.get((target.target, target.profile))
        if due(target, last_run, last_enqueued, now):
            job = enqueue_scan(q, config, target.name, OPERATOR)
            redis.set(key, now.isoformat())
            log.info("scheduled scan of %s enqueued as job %s", target.name, job.id)
            enqueued.append(target.name)
    return enqueued


def _text(raw: object) -> str | None:
    if raw is None:
        return None
    return raw.decode() if isinstance(raw, bytes) else str(raw)


def run_forever(
    config: ServiceConfig,
    q: Queue,
    interval: timedelta = timedelta(minutes=1),
    sleep: Callable[[float], None] = time.sleep,
    rounds: int | None = None,
) -> None:
    done = 0
    while rounds is None or done < rounds:
        try:
            tick(config, q)
        except Exception:  # noqa: BLE001 - keep scheduling; the next round may succeed
            log.exception("scheduler round failed")
        done += 1
        if rounds is None or done < rounds:
            sleep(interval.total_seconds())
