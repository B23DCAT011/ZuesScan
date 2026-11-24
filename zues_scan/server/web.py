"""The web API and dashboard (FastAPI, D4) — read results, queue scans, decide findings.

    GET  /                               the dashboard (static page, no build step)
    GET  /healthz                        liveness for Docker / a load balancer (no auth)
    POST /api/v1/session                 sign in with a token: opens a session (cookie)
    DELETE /api/v1/session               sign out: ends it on the server
    GET  /api/v1/me | targets | jobs | runs | findings | hosts | audit   (viewer)
    GET  /api/v1/runs/{id}[/report.html|/sarif]                          (viewer)
    POST /api/v1/scans  {"target": "<name in service.toml>"}             (operator)
    POST /api/v1/findings/{id}/decision  {"action": "claim_fixed", ...}  (operator)
    GET|PUT|DELETE /api/v1/admin/...     settings and sessions           (admin)

Who may do what comes from `service.toml` and the dashboard's settings: a token (sent as
`Authorization: Bearer`, or once to `/api/v1/session` by the browser) is hashed and
compared with the stored SHA-256 digests. The configuration is re-read when it changes,
so a revoked token or a removed target stops working at the next request; if an edit
breaks the file, the API refuses every request until it is fixed (fail closed, never
"keep the old tokens"). Wrong tokens are counted per address; too many lock it out for a
while (`sessions.Throttle`).

The browser never keeps the token: signing in opens a session held by the server
(`sessions`), and the HttpOnly, SameSite=Strict cookie holds only that session's random
secret, which page scripts cannot read. Requests that change something and arrive with
that cookie must also carry the `X-ZuesScan: 1` header, which another site cannot add
without a CORS preflight this server never grants: that is the CSRF defence.

A scan request names a configured target; it cannot bring an address, a scope or
options (the request model forbids extra fields). What is scanned is decided by
`service.toml` and checked again by the worker and the scope guard.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import logging
import os
import re
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from redis import Redis
from rq import Queue
from rq.exceptions import NoSuchJobError
from rq.job import Job

from zues_scan import __version__, priority
from zues_scan.inventory import ACTIVE, Status
from zues_scan.inventory_store import FindingRow, InventoryError
from zues_scan.plugins import registry as plugin_registry
from zues_scan.profiles import BUILTIN as BUILTIN_PROFILES
from zues_scan.report import render_html, stored_model
from zues_scan.report.html import page_csp
from zues_scan.report.sarif import to_sarif
from zues_scan.server import managed, notify, sessions
from zues_scan.server import queue as rkqueue
from zues_scan.server.config import DASHBOARD, ConfigError, ServiceConfig, Token, load_config
from zues_scan.server.sessions import Session, stamp
from zues_scan.storage import Storage, StorageError, prefer_wal

log = logging.getLogger(__name__)

COOKIE = "zues_session"
CSRF_HEADER = "X-ZuesScan"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Sent with a 401 for a cookie that no longer opens a session: the browser forgets it.
CLEAR_COOKIE = f"{COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=strict"

# The dashboard loads only its own files and talks only to this server.
DASHBOARD_CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)
# Everything else (JSON) is data, never a page.
API_CSP = "default-src 'none'; frame-ancestors 'none'"

STATIC = {
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
}
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


# --- configuration, re-read when it changes ----------------------------------------------------


class LiveConfig:
    """`service.toml` and the dashboard's configuration, re-read at the first request after
    either changed (the file on disk; the database's `managed_meta.version`, which another
    process — `zues user add` — may have changed)."""

    def __init__(self, path: str, redis: Redis | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._config: ServiceConfig | None = load_config(path)  # a bad file: do not start
        self._error: str | None = None
        self._mtime = self._stat()
        self._redis = redis  # given by tests; otherwise one connection per URL
        self._connections: dict[str, Redis] = {}

    def _stat(self) -> int | None:
        try:
            return os.stat(self.path).st_mtime_ns
        except OSError:
            return None

    def _managed_version(self) -> int | None:
        if self._config is None:
            return None
        try:
            uri = Path(self._config.db).resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                row = conn.execute(
                    "SELECT value FROM managed_meta WHERE key = 'version'"
                ).fetchone()
        except sqlite3.Error:
            return None  # no database yet, or one from before schema 14
        return int(row[0]) if row else None

    def get(self) -> ServiceConfig:
        mtime = self._stat()
        version = self._managed_version()
        known = self._config.managed_version if self._config else None
        if mtime != self._mtime or (version is not None and version != known):
            with self._lock:
                self._reload(mtime)
        if self._config is None:
            raise HTTPException(503, "the service configuration is invalid; see the server log")
        return self._config

    def _reload(self, mtime: int | None) -> None:
        self._mtime = mtime
        try:
            self._config = load_config(self.path)
        except ConfigError as exc:
            # Fail closed: keeping the old file's tokens would keep a revoked one working.
            self._config = None
            self._error = str(exc)
            log.error("service config %s is invalid, refusing requests: %s", self.path, exc)
            return
        self._error = None
        log.info("service config %s reloaded", self.path)

    @property
    def error(self) -> str | None:
        return self._error

    def queue(self, config: ServiceConfig) -> Queue:
        if self._redis is not None:
            return rkqueue.queue(config, connection=self._redis)
        connection = self._connections.get(config.redis_url)
        if connection is None:
            connection = self._connections.setdefault(config.redis_url, rkqueue.connect(config))
        return rkqueue.queue(config, connection=connection)


# --- who is asking -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Caller:
    name: str
    role: str
    session: int | None = None  # the session's id when signed in with the browser


def match_token(config: ServiceConfig, token: str) -> Token | None:
    """The configured token whose SHA-256 is that of `token`, compared in constant time."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    found = None
    for candidate in config.tokens:  # no early exit: the time does not tell which matched
        if hmac.compare_digest(digest, candidate.sha256):
            found = candidate
    return found


def live(request: Request) -> LiveConfig:
    holder: LiveConfig = request.app.state.live
    return holder


def current_config(holder: Annotated[LiveConfig, Depends(live)]) -> ServiceConfig:
    return holder.get()


def client_address(request: Request) -> str:
    """The caller's address (behind a trusted proxy: the one it forwarded)."""
    return request.client.host if request.client else "unknown"


def _throttle_args(request: Request, config: ServiceConfig) -> tuple[Any, str, str]:
    holder: LiveConfig = request.app.state.live
    redis = holder.queue(config).connection  # no round trip yet: failures are handled later
    return redis, f"zues:{config.queue}:auth", client_address(request)


def _brake(request: Request, config: ServiceConfig) -> None:
    """Refuse a sign-in from a locked-out address before looking at its token (429)."""
    throttle: sessions.Throttle = request.app.state.throttle
    seconds = throttle.locked(*_throttle_args(request, config))
    if seconds:
        minutes = max(1, -(-seconds // 60))
        raise HTTPException(
            429,
            f"too many failed sign-ins from your address; try again in {minutes} minute(s)",
            {"Retry-After": str(seconds)},
        )


def _wrong_token(request: Request, config: ServiceConfig) -> None:
    """Count a wrong token; lock the address out (logged, audited) if it was one too many."""
    throttle: sessions.Throttle = request.app.state.throttle
    redis, prefix, client = _throttle_args(request, config)
    log.warning("failed sign-in from %s", client, extra={"event": "auth.failed"})
    failures = throttle.failed(redis, prefix, client)
    if not failures:
        return
    log.warning(
        "%s locked out for %d s after %d failed sign-ins",
        client,
        sessions.LOCKOUT,
        failures,
        extra={"event": "auth.locked"},
    )
    try:
        with _writable(config) as store:
            store.record_lockout(
                client,
                failures=failures,
                seconds=sessions.LOCKOUT,
                at=stamp(sessions.now()),
                alert=(
                    notify.locked_out(client, failures, sessions.LOCKOUT)
                    if config.notify.webhook
                    else None
                ),
            )
    except (StorageError, sqlite3.Error) as exc:  # the lock holds; only the record is lost
        log.error("could not audit the lock-out of %s: %s", client, exc)


def _token_of(config: ServiceConfig, session: Session) -> Token | None:
    """The token a session was opened with, if it is still configured unchanged."""
    for token in config.tokens:
        if token.name == session.token_name and hmac.compare_digest(
            token.sha256, session.token_sha256
        ):
            return token
    return None  # revoked, or re-issued under the same name: the session is over


def _session_caller(request: Request, config: ServiceConfig) -> Caller | None:
    secret = request.cookies.get(COOKIE, "")
    if not secret or len(secret) > 128:
        return None
    with opened(config) as store:
        row = store.session_by_secret(sessions.digest(secret)) if store else None
        if store is None or row is None:
            return None
        session = Session.from_row(row)
        at = sessions.now()
        token = _token_of(config, session)
        if session.ended(at) or token is None:
            return None  # the row goes at the next sign-in's clean-up
        refresh = request.headers.get(sessions.REFRESH_HEADER) == "1"
        if not refresh and at - session.last_seen_at >= sessions.TOUCH_EVERY:
            try:
                store.touch_session(session.id, stamp(at))
            except sqlite3.Error as exc:  # busy: the next request touches it instead
                log.warning("could not record the use of session #%d: %s", session.id, exc)
    return Caller(token.name, token.role, session=session.id)


def caller(request: Request, config: Annotated[ServiceConfig, Depends(current_config)]) -> Caller:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        _brake(request, config)
        token = match_token(config, value.strip())
        if token is None:
            _wrong_token(request, config)
            raise HTTPException(401, "a valid token is required", {"WWW-Authenticate": "Bearer"})
        return Caller(token.name, token.role)
    if COOKIE in request.cookies:
        who = _session_caller(request, config)
        if who is None:
            raise HTTPException(
                401,
                "your session has ended; sign in again",
                {"WWW-Authenticate": "Bearer", "Set-Cookie": CLEAR_COOKIE},
            )
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, f"missing the {CSRF_HEADER} header")
        return who
    raise HTTPException(401, "a valid token is required", {"WWW-Authenticate": "Bearer"})


def operator(who: Annotated[Caller, Depends(caller)]) -> Caller:
    if not managed.can(who.role, "operator"):
        raise HTTPException(403, "this needs an operator token")
    return who


def admin(who: Annotated[Caller, Depends(caller)]) -> Caller:
    if not managed.can(who.role, "admin"):
        raise HTTPException(403, "this needs an admin token")
    return who


Config = Annotated[ServiceConfig, Depends(current_config)]
Viewer = Annotated[Caller, Depends(caller)]
Operator = Annotated[Caller, Depends(operator)]
Admin = Annotated[Caller, Depends(admin)]


@contextmanager
def opened(config: ServiceConfig) -> Iterator[Storage | None]:
    """The database, or None if nothing has been scanned yet (never created here)."""
    if not Path(config.db).is_file():
        yield None
        return
    with Storage(config.db) as store:
        yield store


# --- request bodies ----------------------------------------------------------------------------


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=512)


class ScanRequest(BaseModel):
    """Only a name: the address, scope and options come from service.toml."""

    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=64)


class ScopeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=managed.MAX_SCOPE_BYTES)


class TargetBody(BaseModel):
    """A dashboard target. No server paths (credentials, profile files): service.toml only."""

    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=253)
    scope: str = Field(min_length=1, max_length=64)
    profile: str = Field(default="standard", max_length=32)
    every: str | None = Field(default=None, max_length=16)
    cron: str | None = Field(default=None, max_length=80)
    engagement: str | None = Field(default=None, max_length=200)
    scanners: list[str] = Field(default_factory=list, max_length=8)
    checks: list[str] = Field(default_factory=list, max_length=16)
    discoverers: list[str] = Field(default_factory=list, max_length=8)
    discover: bool = False
    discover_limit: int | None = Field(default=None, ge=1, le=100_000)
    ipv4_only: bool = False


class TokenBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    role: Literal["viewer", "operator", "admin"]


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["claim_fixed", "accept", "reopen"]
    note: str | None = Field(default=None, max_length=2000)
    until: str | None = Field(default=None, max_length=10)  # YYYY-MM-DD, for "accept"


# --- the API -----------------------------------------------------------------------------------

api = APIRouter(prefix="/api/v1")


@api.post("/session")
def login(body: Login, request: Request, response: Response, config: Config) -> dict[str, str]:
    _brake(request, config)
    token = match_token(config, body.token)
    if token is None:
        _wrong_token(request, config)
        raise HTTPException(401, "unknown token")
    throttle: sessions.Throttle = request.app.state.throttle
    throttle.succeeded(*_throttle_args(request, config))
    secret = sessions.new_secret()
    at = sessions.now()
    client = client_address(request)
    with _writable(config) as store:
        store.prune_sessions(expired_before=stamp(at), idle_before=stamp(at - sessions.IDLE))
        # Signing in again from this browser replaces its session: one at a time.
        old = request.cookies.get(COOKIE, "")
        row = store.session_by_secret(sessions.digest(old)) if 0 < len(old) <= 128 else None
        if row is not None:
            store.close_session(
                int(row["id"]), actor=row["token_name"], action="signed out", at=stamp(at)
            )
        session_id = store.open_session(
            secret_sha256=sessions.digest(secret),
            token_name=token.name,
            token_sha256=token.sha256,
            at=stamp(at),
            expires_at=stamp(at + sessions.LIFETIME),
            client=client,
            user_agent=request.headers.get("user-agent", "")[:200] or None,
        )
    response.set_cookie(
        COOKIE,
        secret,
        max_age=int(sessions.LIFETIME.total_seconds()),
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    log.info("%s signed in from %s (session #%d)", token.name, client, session_id)
    return {"name": token.name, "role": token.role}


@api.delete("/session", status_code=204)
def logout(request: Request, response: Response, config: Config) -> None:
    secret = request.cookies.get(COOKIE, "")
    if 0 < len(secret) <= 128:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, f"missing the {CSRF_HEADER} header")
        with opened(config) as store:
            row = store.session_by_secret(sessions.digest(secret)) if store else None
            if store is not None and row is not None:
                store.close_session(
                    int(row["id"]),
                    actor=row["token_name"],
                    action="signed out",
                    at=stamp(sessions.now()),
                )
                log.info("%s signed out (session #%d)", row["token_name"], row["id"])
    response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")


@api.get("/me")
def me(who: Viewer) -> dict[str, str]:
    return {"name": who.name, "role": who.role, "version": __version__}


@api.get("/targets")
def targets(who: Viewer, config: Config) -> list[dict[str, Any]]:
    with opened(config) as store:
        starts = store.latest_starts() if store else {}
    return [
        {
            "name": t.name,
            "target": t.target,
            "profile": t.profile,
            "every_seconds": int(t.every.total_seconds()) if t.every else None,
            "cron": t.cron.text if t.cron else None,
            "engagement": t.engagement,
            "nuclei": t.nuclei or "nuclei" in t.checks,
            "discover": t.discover or bool(t.discoverers),
            "checks": sorted({*t.checks, *(["nuclei"] if t.nuclei else [])}),
            "authenticated": t.credentials is not None,  # never the key file's path
            "last_started_at": starts.get((t.target, t.profile)),
            "source": t.source,
        }
        for t in config.targets.values()
    ]


@api.post("/scans", status_code=202)
def request_scan(
    body: ScanRequest, who: Operator, config: Config, holder: Annotated[LiveConfig, Depends(live)]
) -> dict[str, Any]:
    if body.target not in config.targets:
        raise HTTPException(404, f"no target named {body.target!r} in the service config")
    job = rkqueue.enqueue_scan(holder.queue(config), config, body.target, who.name)
    log.info("%s queued a scan of %s as job %s", who.name, body.target, job.id)
    return {"job": rkqueue.info(job).as_dict()}


@api.get("/jobs")
def jobs(
    who: Viewer,
    config: Config,
    holder: Annotated[LiveConfig, Depends(live)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    return [i.as_dict() for i in rkqueue.recent_jobs(holder.queue(config), limit)]


@api.get("/jobs/{job_id}")
def job(
    job_id: str, who: Viewer, config: Config, holder: Annotated[LiveConfig, Depends(live)]
) -> dict[str, Any]:
    if not _JOB_ID.fullmatch(job_id):
        raise HTTPException(404, "no such job")
    q = holder.queue(config)
    try:
        found = Job.fetch(job_id, connection=q.connection)
    except NoSuchJobError:
        raise HTTPException(404, "no such job") from None
    if found.origin != q.name:
        raise HTTPException(404, "no such job")  # another queue on the same Redis
    return rkqueue.info(found).as_dict()


@api.get("/runs")
def runs(
    who: Viewer, config: Config, limit: Annotated[int, Query(ge=1, le=1000)] = 100
) -> list[dict[str, Any]]:
    with opened(config) as store:
        return [dataclasses.asdict(r) for r in store.list_runs(limit)] if store else []


def _model(config: ServiceConfig, run_id: int) -> dict[str, Any]:
    with opened(config) as store:
        model = stored_model(store, run_id) if store else None
    if model is None:
        raise HTTPException(404, f"no run #{run_id}")
    return model


@api.get("/runs/{run_id}")
def run(run_id: int, who: Viewer, config: Config) -> dict[str, Any]:
    return _model(config, run_id)


@api.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
def run_report(run_id: int, who: Viewer, config: Config) -> HTMLResponse:
    # The M1 report as it is: one self-contained page with its own strict CSP (sent
    # as a header too, with frame-ancestors, which a <meta> cannot set).
    page = render_html(_model(config, run_id))
    return HTMLResponse(
        page, headers={"Content-Security-Policy": f"{page_csp()}; frame-ancestors 'none'"}
    )


@api.get("/runs/{run_id}/sarif")
def run_sarif(run_id: int, who: Viewer, config: Config) -> JSONResponse:
    return JSONResponse(
        to_sarif(_model(config, run_id)),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="zues-run-{run_id}.sarif"'},
    )


def _finding(row: FindingRow) -> dict[str, Any]:
    finding = row.as_finding()
    return {
        **dataclasses.asdict(row),
        "priority": str(priority.priority(finding)),
        "priority_reason": priority.reason(finding),
    }


@api.get("/findings")
def findings(
    who: Viewer,
    config: Config,
    status: Annotated[list[Status] | None, Query()] = None,
    all: bool = False,  # noqa: A002 - the query parameter's name
) -> list[dict[str, Any]]:
    statuses = None if all else {str(s) for s in (status or ACTIVE)}
    with opened(config) as store:
        rows = store.inventory_findings(statuses) if store else []
    rows.sort(key=lambda r: priority.sort_key(r.as_finding()))
    return [_finding(r) for r in rows]


@api.get("/findings/{finding_id}")
def finding(finding_id: int, who: Viewer, config: Config) -> dict[str, Any]:
    with opened(config) as store:
        row = store.inventory_finding(finding_id) if store else None
        if store is None or row is None:
            raise HTTPException(404, f"no finding #{finding_id}")
        history = store.finding_history(finding_id)
    return {**_finding(row), "history": [dataclasses.asdict(e) for e in history]}


@api.post("/findings/{finding_id}/decision")
def decide(finding_id: int, body: Decision, who: Operator, config: Config) -> dict[str, Any]:
    with opened(config) as store:
        if store is None or store.inventory_finding(finding_id) is None:
            raise HTTPException(404, f"no finding #{finding_id}")
        try:
            new = store.decide_finding(
                finding_id, body.action, actor=who.name, note=body.note, until=body.until
            )
        except InventoryError as exc:
            raise HTTPException(409, str(exc)) from None
    log.info("%s: %s on finding #%d, now %s", who.name, body.action, finding_id, new)
    return {"finding_id": finding_id, "status": str(new)}


# --- administration: what to scan, how, and who may (admin tokens only) -----------------------


@api.get("/admin/config")
def admin_config(who: Admin, config: Config) -> dict[str, Any]:
    """Everything the settings page shows: scopes, targets, tokens, plugins, profiles."""
    registry = plugin_registry.load()
    scopes = []
    for name, text in sorted(config.scopes.items()):
        try:
            facts = managed.describe_scope(managed.read_scope(name, text))
        except managed.ManagedError as exc:
            facts = {"error": str(exc)}
        users = sorted(
            t.name for t in config.targets.values() if t.scope_text is not None and t.scope == name
        )
        scopes.append({"name": name, "source": DASHBOARD, "text": text, "used_by": users, **facts})
    files = sorted({t.scope for t in config.targets.values() if t.scope_text is None})
    for path in files:
        users = sorted(
            t.name for t in config.targets.values() if t.scope_text is None and t.scope == path
        )
        scopes.append({"name": path, "source": "file", "used_by": users})  # not its content
    return {
        "scopes": scopes,
        "targets": [
            _target_settings(t) for t in sorted(config.targets.values(), key=lambda t: t.name)
        ],
        "tokens": [
            {"name": t.name, "role": t.role, "source": t.source, "you": t.name == who.name}
            for t in sorted(config.tokens, key=lambda t: t.name)
        ],
        "plugins": [
            {
                "name": s.name,
                "kind": s.kind,
                "activity": str(s.activity),
                "summary": s.summary,
                "ready": s.binary is None or managed._found(s.binary),
                "needs": list(s.needs),
            }
            for s in registry.plugins.values()
        ],
        "profiles": [
            {"name": p.name, "description": p.description} for p in BUILTIN_PROFILES.values()
        ],
        "sessions": _live_sessions(config, who),
        "alerts": _alerts(config, 20),
        "problems": list(config.problems),
    }


def _target_settings(t: Any) -> dict[str, Any]:
    every = int(t.every.total_seconds()) if t.every else None
    return {
        "name": t.name,
        "source": t.source,
        "target": t.target,
        "scope": t.scope if t.scope_text is not None else None,  # a file target: not its path
        "profile": t.profile,
        "every": _every_text(every),
        "cron": t.cron.text if t.cron else None,
        "engagement": t.engagement,
        "scanners": list(t.scanners) or ["nmap"],
        "checks": sorted({*t.checks, *(["nuclei"] if t.nuclei else [])}),
        "discoverers": list(t.discoverers),
        "discover": t.discover,
        "discover_limit": t.discover_limit,
        "ipv4_only": t.ipv4_only,
    }


def _every_text(seconds: int | None) -> str | None:
    if not seconds:
        return None
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds // 60}m"


@contextmanager
def _writable(config: ServiceConfig) -> Iterator[Storage]:
    """The database, created if needed (an admin may configure before the first scan)."""
    with Storage(config.db) as store:
        yield store


def _refused(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(404, str(exc).strip("'\""))
    return HTTPException(422, str(exc))


@api.put("/admin/scopes/{name}")
def put_scope(name: str, body: ScopeBody, who: Admin, config: Config) -> dict[str, Any]:
    try:
        with _writable(config) as store:
            saved = managed.save_scope(store, config, name, body.text, who.name)
    except managed.ManagedError as exc:
        raise _refused(exc) from None
    log.info("%s saved the scope %s", who.name, name)
    return {"name": saved.name, "warnings": saved.warnings}


@api.delete("/admin/scopes/{name}", status_code=204)
def delete_scope(name: str, who: Admin, config: Config) -> None:
    try:
        with _writable(config) as store:
            managed.delete_scope(store, config, name, who.name)
    except (managed.ManagedError, LookupError) as exc:
        raise _refused(exc) from None
    log.info("%s deleted the scope %s", who.name, name)


@api.put("/admin/targets/{name}")
def put_target(name: str, body: TargetBody, who: Admin, config: Config) -> dict[str, Any]:
    try:
        with _writable(config) as store:
            saved = managed.save_target(store, config, name, body.model_dump(), who.name)
    except managed.ManagedError as exc:
        raise _refused(exc) from None
    log.info("%s saved the target %s", who.name, name)
    return {"name": saved.name, "warnings": saved.warnings}


@api.delete("/admin/targets/{name}", status_code=204)
def delete_target(name: str, who: Admin, config: Config) -> None:
    try:
        with _writable(config) as store:
            managed.delete_target(store, config, name, who.name)
    except (managed.ManagedError, LookupError) as exc:
        raise _refused(exc) from None
    log.info("%s deleted the target %s", who.name, name)


@api.post("/admin/tokens", status_code=201)
def post_token(body: TokenBody, who: Admin, config: Config) -> dict[str, Any]:
    try:
        with _writable(config) as store:
            token = managed.create_token(store, config, body.name, body.role, who.name)
    except managed.ManagedError as exc:
        raise _refused(exc) from None
    log.info("%s created the %s token %s", who.name, body.role, body.name)
    # Shown this once: only its SHA-256 is kept.
    return {"name": body.name.strip(), "role": body.role, "token": token}


@api.delete("/admin/tokens/{name}", status_code=204)
def delete_token(name: str, who: Admin, config: Config) -> None:
    try:
        with _writable(config) as store:
            managed.delete_token(store, config, name, who.name)
    except (managed.ManagedError, LookupError) as exc:
        raise _refused(exc) from None
    log.info("%s deleted the token %s", who.name, name)


def _live_sessions(config: ServiceConfig, who: Caller) -> list[dict[str, Any]]:
    """The sessions still open: not ended by time, their token unchanged."""
    at = sessions.now()
    with opened(config) as store:
        rows = store.sessions() if store else []
    found = []
    for row in rows:
        session = Session.from_row(row)
        token = _token_of(config, session)
        if token is None or session.ended(at):
            continue
        found.append({**session.as_dict(), "role": token.role, "you": session.id == who.session})
    return found


@api.get("/admin/sessions")
def admin_sessions(who: Admin, config: Config) -> list[dict[str, Any]]:
    return _live_sessions(config, who)


@api.delete("/admin/sessions/{session_id}", status_code=204)
def end_session(session_id: int, who: Admin, config: Config) -> None:
    with opened(config) as store:
        ended = store is not None and store.close_session(
            session_id, actor=who.name, action="session ended", at=stamp(sessions.now())
        )
    if not ended:
        raise HTTPException(404, f"no session #{session_id}")
    log.info("%s ended session #%d", who.name, session_id)


def _alerts(config: ServiceConfig, limit: int) -> dict[str, Any]:
    """Where alerts go (the webhook's host only: its URL is a secret) and the latest ones."""
    with opened(config) as store:
        rows = store.alert_rows(limit) if store else []
    webhook = config.notify.webhook
    return {
        "webhook": (urlsplit(webhook).hostname or "?") if webhook else None,
        "signed": bool(config.notify.secret),
        "min_priority": config.notify.min_priority,
        "failed_scans": config.notify.failed_scans,
        "latest": [notify.describe(r) for r in rows],
    }


def _alert(config: ServiceConfig, alert_id: int) -> dict[str, Any]:
    with opened(config) as store:
        rows = store.alert_rows(ids=[alert_id]) if store else []
    if not rows:
        raise HTTPException(404, f"no alert #{alert_id}")
    return notify.describe(rows[0])


@api.get("/admin/alerts")
def admin_alerts(
    who: Admin, config: Config, limit: Annotated[int, Query(ge=1, le=500)] = 50
) -> dict[str, Any]:
    return _alerts(config, limit)


@api.post("/admin/alerts/test")
def send_test_alert(who: Admin, config: Config) -> dict[str, Any]:
    """Queue a test alert and send it now: whether the webhook (and its signature) works."""
    if not config.notify.webhook:
        raise HTTPException(
            409, "no webhook is set: [notify] webhook in service.toml, or ZUES_WEBHOOK"
        )
    alert_id = notify.queue(config, notify.delivery_test(who.name))
    if alert_id is None:
        raise HTTPException(503, "the alert could not be queued; see the server log")
    notify.flush(config, ids=[alert_id])
    log.info("%s sent a test alert (#%d)", who.name, alert_id)
    return _alert(config, alert_id)


@api.post("/admin/alerts/{alert_id}/retry")
def retry_alert(alert_id: int, who: Admin, config: Config) -> dict[str, Any]:
    """Send an alert that is waiting or was given up now, instead of at its next try."""
    with opened(config) as store:
        due = store is not None and store.retry_alert(alert_id, notify.stamp(notify.now()))
    if not due:
        raise HTTPException(404, f"no alert #{alert_id} waiting to be sent")
    notify.flush(config, ids=[alert_id])
    log.info("%s retried alert #%d", who.name, alert_id)
    return _alert(config, alert_id)


@api.get("/hosts")
def hosts(who: Viewer, config: Config) -> list[dict[str, Any]]:
    with opened(config) as store:
        return store.inventory_hosts() if store else []


@api.get("/audit")
def audit(
    who: Viewer, config: Config, limit: Annotated[int, Query(ge=1, le=5000)] = 200
) -> dict[str, Any]:
    with opened(config) as store:
        if store is None:
            return {"chain": None, "events": []}
        report = store.verify_audit()
        events = store.audit_events()
    return {
        "chain": {
            "events": report.events,
            "head": report.head,
            "intact": report.intact,
            "problems": report.problems,
        },
        "events": [
            {"id": event_id, **event.fields(), "hash": digest}
            for event_id, event, digest in reversed(events[-limit:])
        ],
    }


# --- the application ---------------------------------------------------------------------------


def create_app(config_path: str, *, redis: Redis | None = None) -> FastAPI:
    """The web application for `config_path`; raises ConfigError if the file is invalid."""
    app = FastAPI(
        title="ZuesScan",
        version=__version__,
        docs_url=None,  # Swagger UI would load scripts from a CDN: the schema is enough
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.live = LiveConfig(config_path, redis)
    app.state.throttle = sessions.Throttle()
    app.include_router(api)

    @app.exception_handler(StorageError)
    def storage_error(request: Request, exc: StorageError) -> JSONResponse:
        log.error("database error on %s: %s", request.url.path, exc)
        return JSONResponse({"detail": "the database is unavailable"}, status_code=503)

    for error in rkqueue.UNREACHABLE:

        @app.exception_handler(error)
        def queue_error(request: Request, exc: Exception) -> JSONResponse:
            log.error("Redis error on %s: %s", request.url.path, exc)
            return JSONResponse({"detail": "the scan queue is unavailable"}, status_code=503)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        headers = response.headers
        headers.setdefault("Content-Security-Policy", API_CSP)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> HTMLResponse:
        return HTMLResponse(
            _static("index.html"), headers={"Content-Security-Policy": DASHBOARD_CSP}
        )

    @app.get("/static/{name}", include_in_schema=False)
    def static(name: str) -> Response:
        if name not in STATIC:
            raise HTTPException(404)
        return Response(_static(name), media_type=STATIC[name])

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> Response:
        return Response(status_code=204)  # no icon; and no 404 in every browser console

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> JSONResponse:
        holder: LiveConfig = app.state.live
        checks = {"config": True, "database": True, "queue": True}
        try:
            config = holder.get()
        except HTTPException:
            checks = {"config": False, "database": False, "queue": False}
        else:
            checks["database"] = _database_ok(config.db)
            try:
                checks["queue"] = bool(holder.queue(config).connection.ping())
            except rkqueue.UNREACHABLE:
                checks["queue"] = False
        ok = all(checks.values())
        return JSONResponse(
            {"status": "ok" if ok else "degraded", "checks": checks},
            status_code=200 if ok else 503,
        )

    return app


def _database_ok(path: str) -> bool:
    """Readable, or not created yet (nothing scanned): never created or changed here."""
    if not Path(path).is_file():
        return True
    try:
        conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
        try:
            conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return True


def _static(name: str) -> str:
    return resources.files("zues_scan.server").joinpath("static", name).read_text("utf-8")


def serve(config_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the web server (uvicorn) until interrupted."""
    import uvicorn

    app = create_app(config_path)
    prefer_wal(app.state.live.get().db)  # e.g. after a restore from a backup
    # proxy_headers: behind a TLS reverse proxy, take the scheme from X-Forwarded-Proto
    # (only from the addresses in FORWARDED_ALLOW_IPS, 127.0.0.1 by default), so that
    # the session cookie is marked Secure.
    uvicorn.run(app, host=host, port=port, proxy_headers=True, server_header=False)
