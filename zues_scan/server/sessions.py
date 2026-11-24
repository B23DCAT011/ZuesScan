"""The dashboard's sign-in: sessions held by the server, and a brake on guessing (G23).

**Sessions.** Signing in with a token opens a session: the browser's cookie holds a random
secret (256 bits), the database only its SHA-256, next to the name and SHA-256 of the token
it was opened with. A session ends

- when its owner signs out (the row is deleted: a copied cookie stops working too);
- after `IDLE` without use, and `LIFETIME` after signing in, whatever happens;
- when its token is revoked or re-issued (checked at every request against the live
  configuration: no list of sessions to keep in step);
- when an admin ends it (Settings → Sessions).

The dashboard's own periodic refresh says so (`X-ZuesScan-Refresh: 1`) and does not count
as use, so a tab left open still goes idle.

**Failed sign-ins.** Each wrong token — at `POST /api/v1/session` or as `Authorization:
Bearer` — counts against the client's address. `LIMIT` failures within `WINDOW` lock that
address out for `LOCKOUT`: every sign-in from it is refused with 429, even with a right
token, so the answer tells a guesser nothing. Tokens have 256 bits, so this is not what
keeps them safe; it keeps a guesser (or a misconfigured script) from hammering the
service unnoticed: the lock-out is logged and audited. The counts live in Redis, shared by
every web process, and expire on their own; if Redis cannot be reached they are kept in
this process instead (and that is logged), never skipped.

Behind a reverse proxy the client's address is the one the proxy forwarded — uvicorn takes
it from `X-Forwarded-For` only when the proxy is in FORWARDED_ALLOW_IPS. A lock-out then
hits everyone behind one NAT address: the price of a per-address brake, documented in G23.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from redis import exceptions as redis_errors

log = logging.getLogger(__name__)

IDLE = timedelta(minutes=30)
LIFETIME = timedelta(hours=8)
TOUCH_EVERY = timedelta(minutes=1)  # how stale `last_seen_at` may get before it is written

LIMIT = 10  # failed sign-ins from one address ...
WINDOW = 15 * 60  # ... within this many seconds ...
LOCKOUT = 15 * 60  # ... lock it out for this long

REFRESH_HEADER = "X-ZuesScan-Refresh"

# What a Redis call can raise when the server is down, slow or refuses (e.g. read-only).
REDIS_FAILED = (redis_errors.ConnectionError, redis_errors.TimeoutError, redis_errors.ResponseError)


def now() -> datetime:
    """The current time (UTC); the one clock of this module, replaced in tests."""
    return datetime.now(UTC)


def stamp(at: datetime) -> str:
    """A stored time: ISO 8601 UTC to the second, so that text order is time order."""
    return at.astimezone(UTC).isoformat(timespec="seconds")


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Session:
    id: int
    token_name: str
    token_sha256: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    client: str | None
    user_agent: str | None

    @classmethod
    def from_row(cls, row: Any) -> Session:
        return cls(
            id=int(row["id"]),
            token_name=row["token_name"],
            token_sha256=row["token_sha256"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            client=row["client"],
            user_agent=row["user_agent"],
        )

    def ended(self, at: datetime) -> str | None:
        """Why the session is over at `at` by itself (None: it is not)."""
        if at >= self.expires_at:
            return "expired"
        if at - self.last_seen_at >= IDLE:
            return "idle"
        return None

    def idle_until(self) -> datetime:
        return min(self.last_seen_at + IDLE, self.expires_at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.token_name,
            "created_at": stamp(self.created_at),
            "last_seen_at": stamp(self.last_seen_at),
            "expires_at": stamp(self.expires_at),
            "idle_until": stamp(self.idle_until()),
            "client": self.client,
            "user_agent": self.user_agent,
        }


# --- failed sign-ins ----------------------------------------------------------------------------


class Counter(Protocol):
    """Where failures are counted: Redis (shared) or this process (fallback)."""

    def locked(self, client: str) -> int: ...

    def fail(self, client: str) -> int: ...

    def lock(self, client: str, seconds: int) -> None: ...

    def forget(self, client: str) -> None: ...


class RedisCounter:
    def __init__(self, redis: Any, prefix: str) -> None:
        self.redis = redis
        self.prefix = prefix

    def _keys(self, client: str) -> tuple[str, str]:
        return f"{self.prefix}:fail:{client}", f"{self.prefix}:lock:{client}"

    def locked(self, client: str) -> int:
        ttl = int(self.redis.ttl(self._keys(client)[1]))
        return max(ttl, 0)  # -2: no lock, -1: cannot happen (always set with a TTL)

    def fail(self, client: str) -> int:
        key = self._keys(client)[0]
        # The window starts at the first failure; SET NX EX then INCR never leaves a
        # count without an expiry, even if this process dies between the two.
        pipe = self.redis.pipeline(transaction=True)
        pipe.set(key, 0, ex=WINDOW, nx=True)
        pipe.incr(key)
        return int(pipe.execute()[1])

    def lock(self, client: str, seconds: int) -> None:
        fail, lock = self._keys(client)
        pipe = self.redis.pipeline(transaction=True)
        pipe.set(lock, 1, ex=seconds)
        pipe.delete(fail)
        pipe.execute()

    def forget(self, client: str) -> None:
        self.redis.delete(self._keys(client)[0])


class MemoryCounter:
    """The same counts in this process, for when Redis cannot be reached."""

    MAX_CLIENTS = 10_000  # a flood of addresses cannot grow this without bound

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fails: dict[str, tuple[int, float]] = {}  # client -> (count, window ends)
        self._locks: dict[str, float] = {}  # client -> lock ends

    def _prune(self, at: float) -> None:
        self._fails = {c: v for c, v in self._fails.items() if v[1] > at}
        self._locks = {c: end for c, end in self._locks.items() if end > at}

    def locked(self, client: str) -> int:
        with self._lock:
            end = self._locks.get(client, 0.0)
            return max(int(end - time.monotonic() + 0.999), 0)

    def fail(self, client: str) -> int:
        at = time.monotonic()
        with self._lock:
            if len(self._fails) >= self.MAX_CLIENTS:
                self._prune(at)
            count, ends = self._fails.get(client, (0, at + WINDOW))
            if ends <= at:
                count, ends = 0, at + WINDOW
            self._fails[client] = (count + 1, ends)
            return count + 1

    def lock(self, client: str, seconds: int) -> None:
        with self._lock:
            if len(self._locks) >= self.MAX_CLIENTS:
                self._prune(time.monotonic())
            self._locks[client] = time.monotonic() + seconds
            self._fails.pop(client, None)

    def forget(self, client: str) -> None:
        with self._lock:
            self._fails.pop(client, None)


class Throttle:
    """Failed sign-ins per client address; too many lock the address out for a while."""

    def __init__(self) -> None:
        self.memory = MemoryCounter()
        self._warned = 0.0

    def _counter(self, redis: Any, prefix: str) -> Counter:
        return RedisCounter(redis, prefix) if redis is not None else self.memory

    def _call(self, redis: Any, prefix: str, method: str, *args: Any) -> Any:
        try:
            return getattr(self._counter(redis, prefix), method)(*args)
        except REDIS_FAILED as exc:
            if time.monotonic() - self._warned > 60:  # once a minute, not once a request
                self._warned = time.monotonic()
                log.warning("Redis unavailable (%s): counting failed sign-ins in this process", exc)
            return getattr(self.memory, method)(*args)

    def locked(self, redis: Any, prefix: str, client: str) -> int:
        """Seconds the address is still locked out for (0: it is not)."""
        # Either place may hold a lock: one set while Redis was down still counts.
        return max(int(self._call(redis, prefix, "locked", client)), self.memory.locked(client))

    def failed(self, redis: Any, prefix: str, client: str) -> int:
        """Count a failure; the failures counted if this one locked the address, else 0."""
        count = int(self._call(redis, prefix, "fail", client))
        if count < LIMIT:
            return 0
        self._call(redis, prefix, "lock", client, LOCKOUT)
        return count

    def succeeded(self, redis: Any, prefix: str, client: str) -> None:
        self._call(redis, prefix, "forget", client)
