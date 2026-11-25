"""Scheduled scans: enqueue each target with `every = ...` or `cron = ...` when it is due.

Each scheduled target has a *slot*: the time its last scheduled scan was due, kept in
Redis (so that a restart, or two schedulers by mistake, do not enqueue a scan twice).

- `every`: the next slot is the last one plus `every` — not "when the last scan started"
  or "when it was queued", which would drift later each time a scan waits in the queue or
  a round comes late: a daily scan at 02:00 stays at 02:00. Slots missed while the
  scheduler was down are made up with one scan, not one per missed slot.
- `cron`: the slot is the schedule's latest firing; a newer one than recorded is due (one
  scan for several missed). A target added after today's firing waits for the next one.

Without a recorded slot (a new target, or Redis lost its keys) the run history decides:
stored runs are matched on target *and* profile — a quick hourly scan of a network must
not make its daily full scan look done. Manual scans never move a target's slots.

Each round also sends the alerts still waiting in the outbox (`notify.flush`): those a
worker could not deliver right after its scan, and those raised elsewhere (the web's
lock-outs).

`due()` is a pure function; `tick()` does one round; `run_forever()` loops, re-reading
the configuration at every round: a target added or changed in the dashboard (or in
service.toml) is scheduled without restarting. A configuration that has become invalid
stops the scheduling (logged at every round) until it is fixed — never "keep scheduling
the old targets". Only the Redis URL and the queue's name need a restart.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from redis import Redis
from rq import Queue

from zues_scan.server import notify
from zues_scan.server.config import ConfigError, ServiceConfig, Target
from zues_scan.server.queue import AlreadyQueued, enqueue_scan
from zues_scan.storage import Storage, StorageError

log = logging.getLogger(__name__)

OPERATOR = "scheduler"
_KEY = "zues:scheduler:last:{name}"
_LOCK = "zues:scheduler:lock:{queue}"
_LOCK_SECONDS = 30  # far longer than a round takes; freed at its end anyway


# A cron target with no recorded slot whose latest firing is this recent (and not yet
# scanned) is scanned now: e.g. the scheduler restarted, with Redis emptied, just after it.
CATCH_UP = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class Decision:
    due: bool
    slot: datetime | None  # to record as the target's last slot (None: leave it)


def decide(
    target: Target, last_run: datetime | None, last_slot: datetime | None, now: datetime
) -> Decision:
    """Whether `target` is due at `now`, and which slot that scan (or none) takes."""
    if target.cron is not None:
        latest = target.cron.latest_at_or_before(now)
        if latest is None:
            return Decision(False, None)
        if last_slot is not None:
            return Decision(True, latest) if latest > last_slot else Decision(False, None)
        if (last_run is None or last_run < latest) and now - latest <= CATCH_UP:
            return Decision(True, latest)
        return Decision(False, latest)  # from the next firing on
    if target.every is None:
        return Decision(False, None)
    if last_slot is not None:
        if now - last_slot < target.every:
            return Decision(False, None)
        missed = (now - last_slot) // target.every  # whole periods: one scan for all
        return Decision(True, last_slot + target.every * missed)
    if last_run is None or now - last_run >= target.every:
        return Decision(True, now)  # the first slot: from here on, every `every`
    return Decision(False, None)


def due(
    target: Target, last_run: datetime | None, last_slot: datetime | None, now: datetime
) -> bool:
    return decide(target, last_run, last_slot, now).due


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
        last_slot = datetime.fromisoformat(text) if text else None
        last_run = history.get((target.target, target.profile))
        decision = decide(target, last_run, last_slot, now)
        if decision.due:
            try:
                job = enqueue_scan(q, config, target.name, OPERATOR)
            except AlreadyQueued as exc:
                # Not two scans of one target at once: this slot is skipped (as cron's
                # "no overlap"), the next one comes on schedule.
                log.warning("scheduled scan of %s skipped: %s", target.name, exc)
            else:
                log.info(
                    "scheduled scan of %s (due %s) enqueued as job %s",
                    target.name,
                    decision.slot.isoformat(timespec="minutes") if decision.slot else "now",
                    job.id,
                )
                enqueued.append(target.name)
        if decision.slot is not None:
            redis.set(key, decision.slot.isoformat())
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
    reload: Callable[[], ServiceConfig] | None = None,
) -> None:
    """Run rounds until stopped; with `reload`, each round reads the configuration anew."""
    done = 0
    while rounds is None or done < rounds:
        try:
            current = _reloaded(config, reload)
            if current is not None:
                tick(current, q)
                warn_expiring_tokens(current)
                notify.flush(current)  # alerts that could not be sent yet
        except Exception:  # noqa: BLE001 - keep scheduling; the next round may succeed
            log.exception("scheduler round failed")
        done += 1
        if rounds is None or done < rounds:
            sleep(interval.total_seconds())


# A token this close to its end raises an alert (once a day): what uses it (a CI job, an
# agent) must not stop on a Monday morning without warning.
EXPIRY_WARNING = timedelta(days=7)


def warn_expiring_tokens(config: ServiceConfig, now: datetime | None = None) -> list[str]:
    """Queue an alert for each token expiring within EXPIRY_WARNING; their names."""
    now = now or datetime.now(UTC)
    soon = [
        t
        for t in config.tokens
        if t.expires_at is not None and now < t.expires_at <= now + EXPIRY_WARNING
    ]
    for token in soon:
        assert token.expires_at is not None
        notify.queue(config, notify.token_expiring(token.name, token.role, token.expires_at))
    return [t.name for t in soon]


def _reloaded(
    started: ServiceConfig, reload: Callable[[], ServiceConfig] | None
) -> ServiceConfig | None:
    """The configuration for this round; None (nothing scheduled) if it is invalid now."""
    if reload is None:
        return started
    try:
        config = reload()
    except ConfigError as exc:
        log.error("service configuration is invalid, scheduling nothing until it is fixed: %s", exc)
        return None
    if (config.redis_url, config.queue) != (started.redis_url, started.queue):
        log.warning("the Redis URL or the queue changed: restart the scheduler to use them")
    return config
