"""The web API and dashboard (FastAPI, D4) — read results, queue scans, decide findings.

    GET  /                               the dashboard (static page, no build step)
    GET  /healthz                        liveness for Docker / a load balancer (no auth)
    POST /api/v1/session                 log in with a token: sets an HttpOnly cookie
    GET  /api/v1/me | targets | jobs | runs | findings | hosts | audit   (viewer)
    GET  /api/v1/runs/{id}[/report.html|/sarif]                          (viewer)
    POST /api/v1/scans  {"target": "<name in service.toml>"}             (operator)
    POST /api/v1/findings/{id}/decision  {"action": "claim_fixed", ...}  (operator)

Who may do what comes from `service.toml`: a token (sent as `Authorization: Bearer`,
or once to `/api/v1/session` by the browser) is hashed and compared with the stored
SHA-256 digests. The file is re-read when it changes, so a revoked token or a removed
target stops working at the next request; if an edit breaks the file, the API refuses
every request until it is fixed (fail closed, never "keep the old tokens").

The browser keeps the token in an HttpOnly, SameSite=Strict cookie that page scripts
cannot read. Requests that change something and arrive with that cookie must also
carry the `X-ReconKit: 1` header, which another site cannot add without a CORS
preflight this server never grants: that is the CSRF defence.

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
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from redis import Redis
from rq import Queue
from rq.exceptions import NoSuchJobError
from rq.job import Job

from reconkit import __version__, priority
from reconkit.inventory import ACTIVE, Status
from reconkit.inventory_store import FindingRow, InventoryError
from reconkit.report import render_html, stored_model
from reconkit.report.html import page_csp
from reconkit.report.sarif import to_sarif
from reconkit.server import queue as rkqueue
from reconkit.server.config import ConfigError, ServiceConfig, Token, load_config
from reconkit.storage import Storage, StorageError

log = logging.getLogger(__name__)

COOKIE = "reconkit_session"
CSRF_HEADER = "X-ReconKit"
SESSION_SECONDS = 8 * 3600
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

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
    """`service.toml`, re-read at the first request after it changed on disk."""

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

    def get(self) -> ServiceConfig:
        mtime = self._stat()
        if mtime != self._mtime:
            with self._lock:
                if mtime != self._mtime:
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


def caller(request: Request, config: Annotated[ServiceConfig, Depends(current_config)]) -> Caller:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    via_cookie = False
    if scheme.lower() == "bearer" and value.strip():
        token = match_token(config, value.strip())
    elif COOKIE in request.cookies:
        token = match_token(config, request.cookies[COOKIE])
        via_cookie = True
    else:
        token = None
    if token is None:
        raise HTTPException(401, "a valid token is required", {"WWW-Authenticate": "Bearer"})
    if (
        via_cookie
        and request.method not in SAFE_METHODS
        and (request.headers.get(CSRF_HEADER) != "1")
    ):
        raise HTTPException(403, f"missing the {CSRF_HEADER} header")
    return Caller(token.name, token.role)


def operator(who: Annotated[Caller, Depends(caller)]) -> Caller:
    if who.role != "operator":
        raise HTTPException(403, "this needs an operator token")
    return who


Config = Annotated[ServiceConfig, Depends(current_config)]
Viewer = Annotated[Caller, Depends(caller)]
Operator = Annotated[Caller, Depends(operator)]


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


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["claim_fixed", "accept", "reopen"]
    note: str | None = Field(default=None, max_length=2000)
    until: str | None = Field(default=None, max_length=10)  # YYYY-MM-DD, for "accept"


# --- the API -----------------------------------------------------------------------------------

api = APIRouter(prefix="/api/v1")


@api.post("/session")
def login(body: Login, request: Request, response: Response, config: Config) -> dict[str, str]:
    token = match_token(config, body.token)
    if token is None:
        client = request.client.host if request.client else "?"
        log.warning("failed login from %s", client)
        raise HTTPException(401, "unknown token")
    response.set_cookie(
        COOKIE,
        body.token,
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    log.info("%s logged in", token.name)
    return {"name": token.name, "role": token.role}


@api.delete("/session", status_code=204)
def logout(response: Response) -> None:
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
            "engagement": t.engagement,
            "nuclei": t.nuclei,
            "discover": t.discover,
            "authenticated": t.credentials is not None,  # never the key file's path
            "last_started_at": starts.get((t.target, t.profile)),
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
        headers={"Content-Disposition": f'attachment; filename="reconkit-run-{run_id}.sarif"'},
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
        title="ReconKit",
        version=__version__,
        docs_url=None,  # Swagger UI would load scripts from a CDN: the schema is enough
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.live = LiveConfig(config_path, redis)
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
    return resources.files("reconkit.server").joinpath("static", name).read_text("utf-8")


def serve(config_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the web server (uvicorn) until interrupted."""
    import uvicorn

    app = create_app(config_path)
    # proxy_headers: behind a TLS reverse proxy, take the scheme from X-Forwarded-Proto
    # (only from the addresses in FORWARDED_ALLOW_IPS, 127.0.0.1 by default), so that
    # the session cookie is marked Secure.
    uvicorn.run(app, host=host, port=port, proxy_headers=True, server_header=False)
