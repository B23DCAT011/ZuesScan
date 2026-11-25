"""Alerts: what a person must look at, queued in the database and sent to a webhook (G23).

What raises an alert:

- a scan run that changes the picture: a **fake fix** (claimed fixed, still there), a finding
  that **reappeared**, **new** findings at least as urgent as `min_priority` — one alert per
  run, most serious first;
- a target's scans **failing** `failed_scans` times in a row (once, not at every failure),
  and the first run that **works again** after that;
- a scan **not started**: refused by its scope (e.g. the authorisation expired) or a setting
  that no longer holds — once a day per target and reason;
- a scan **job that failed** without saving a run (an exception, a timeout, a worker that
  died) — once every 6 hours per target and error;
- an address **locked out** of the dashboard after failed sign-ins — once an hour per address;
- a **test** alert sent from Settings.

**Delivery** goes through the database's outbox (`zues_scan.alerts`): a scan's alerts are
saved with its run, then posted — by the worker right after the scan, else by the scheduler
at its next round. A failed POST is tried again after 1, 2, 4 ... minutes (at most an hour
apart; `Retry-After` is honoured), and given up 24 hours after the alert was raised, or at
once on an answer that retrying cannot change (4xx other than 408 / 425 / 429). Delivery
is *at least once*: an alert whose POST succeeded but whose "sent" mark was lost is sent
again, with the same `X-ZuesScan-Delivery` id, on which a receiver can deduplicate.

**Signing.** With `secret` set, every POST carries

    X-ZuesScan-Timestamp: <unix seconds>
    X-ZuesScan-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>." + body)>

so that the receiver can check that the alert comes from this service and is fresh (not a
recorded one replayed): `verify()` is that check. The payload stays Slack-compatible
(`{"text": ...}`) with structured fields for other receivers. Standard library only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from zues_scan import __version__, priority
from zues_scan.alerts import Alert, RunFacts
from zues_scan.inventory_store import FindingEvent
from zues_scan.orchestrator import RunStatus, ScanRun
from zues_scan.server.config import Notify, ServiceConfig
from zues_scan.storage import Storage, StorageError

log = logging.getLogger(__name__)

# POST `body` with `headers` to the URL; raises (urllib.error.HTTPError, OSError, ...) on failure.
Post = Callable[[str, bytes, dict[str, str]], None]

BACKOFF_FIRST = timedelta(minutes=1)
BACKOFF_MAX = timedelta(hours=1)
GIVE_UP_AFTER = timedelta(hours=24)
LEASE = timedelta(minutes=2)  # a claimed alert is not taken by another sender meanwhile
BATCH = 20  # alerts sent per round at most: a dead receiver must not hold a round for long
TIMEOUT = 15  # seconds per POST
TOLERANCE = 300  # seconds a signed alert stays valid for `verify`

DAY, HOUR = 86400, 3600


def now() -> datetime:
    """The current time (UTC); the one clock of this module, replaced in tests."""
    return datetime.now(UTC)


def stamp(at: datetime) -> str:
    return at.astimezone(UTC).isoformat(timespec="seconds")


# --- what raises an alert -----------------------------------------------------------------------


def alerts(
    run: ScanRun, changes: list[FindingEvent], min_priority: str = "P2"
) -> list[dict[str, Any]]:
    """What in this run deserves an alert, most serious first."""
    items: list[dict[str, Any]] = []
    for e in changes:
        if e.event in ("fake_fix", "reappeared"):
            items.append(
                {"kind": e.event, "finding_id": e.finding_id, "title": e.title, "host": e.host}
            )
    new = {e.fingerprint for e in changes if e.event == "new"}
    for asset in run.assets:
        for f in asset.findings:
            p = priority.priority(f)
            if f.fingerprint in new and str(p) <= min_priority:
                items.append(
                    {
                        "kind": "new",
                        "priority": str(p),
                        "title": f.title,
                        "cve": f.cve,
                        "host": asset.host,
                        "why": priority.reason(f),
                    }
                )
    order = {"fake_fix": 0, "reappeared": 1, "new": 2}
    return sorted(items, key=lambda i: (order[i["kind"]], i.get("priority", "")))


def message(target: str, run_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [f"ZuesScan: run #{run_id} of {target} needs attention"]
    for i in items[:20]:
        if i["kind"] == "fake_fix":
            lines.append(f"• FAKE FIX: {i['title']} on {i['host']} was claimed fixed, still there")
        elif i["kind"] == "reappeared":
            lines.append(f"• REAPPEARED: {i['title']} on {i['host']}")
        else:
            lines.append(f"• NEW {i['priority']}: {i['title']} on {i['host']} ({i['why']})")
    if len(items) > 20:
        lines.append(f"… and {len(items) - 20} more")
    return {
        "kind": "run",
        "text": "\n".join(lines),
        "target": target,
        "run_id": run_id,
        "items": items,
    }


class RunAlerts:
    """A scan job's alert policy, called while its run is saved (`Storage.save_run`).

    `items` keeps what the run's findings alert on, whether or not a webhook is set (the
    job's summary counts them); alerts are queued only with a webhook to send them to.
    """

    def __init__(self, notify: Notify, target: str) -> None:
        self.notify = notify
        self.target = target
        self.items: list[dict[str, Any]] = []

    def __call__(self, facts: RunFacts) -> list[Alert]:
        decided: list[Alert] = []
        threshold = self.notify.failed_scans
        if facts.run.status == RunStatus.FAILED:
            if facts.failed_before + 1 == threshold:
                decided.append(scan_failed(self.target, facts, threshold))
        else:
            self.items = alerts(facts.run, facts.changes, self.notify.min_priority)
            if self.items:
                decided.append(Alert("run", message(self.target, facts.run_id, self.items)))
            if facts.failed_before >= threshold:
                decided.append(scan_recovered(self.target, facts))
        return decided if self.notify.webhook else []


def _short(text: str | None, size: int = 300) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= size else text[: size - 1] + "…"


def _key(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:24]


def scan_failed(target: str, facts: RunFacts, failures: int) -> Alert:
    error = _short(facts.run.error)
    return Alert(
        "scan_failed",
        {
            "kind": "scan_failed",
            "text": (
                f"ZuesScan: scans of {target} have failed {failures} times in a row "
                f"(run #{facts.run_id}): {error}"
            ),
            "target": target,
            "run_id": facts.run_id,
            "failures": failures,
            "error": error,
        },
    )


def scan_recovered(target: str, facts: RunFacts) -> Alert:
    return Alert(
        "scan_recovered",
        {
            "kind": "scan_recovered",
            "text": (
                f"ZuesScan: scans of {target} work again (run #{facts.run_id}) after "
                f"{facts.failed_before} failed in a row"
            ),
            "target": target,
            "run_id": facts.run_id,
            "failures": facts.failed_before,
        },
    )


def not_started(target: str, reason: str) -> Alert:
    reason = _short(reason)
    return Alert(
        "not_started",
        {
            "kind": "not_started",
            "text": f"ZuesScan: a scan of {target} was not started: {reason}",
            "target": target,
            "reason": reason,
        },
        dedupe_key=f"not_started:{_key(target, reason)}",
        dedupe_seconds=DAY,
    )


def job_failed(target: str, error: str) -> Alert:
    error = _short(error)
    return Alert(
        "job_failed",
        {
            "kind": "job_failed",
            "text": f"ZuesScan: the scan job of {target} failed without saving a run: {error}",
            "target": target,
            "error": error,
        },
        dedupe_key=f"job_failed:{_key(target, error)}",
        dedupe_seconds=6 * HOUR,
    )


def locked_out(client: str, failures: int, seconds: int) -> Alert:
    minutes = max(1, seconds // 60)
    return Alert(
        "locked_out",
        {
            "kind": "locked_out",
            "text": (
                f"ZuesScan: {client} was locked out of the dashboard for {minutes} minutes "
                f"after {failures} failed sign-ins"
            ),
            "client": client,
            "failures": failures,
        },
        dedupe_key=f"locked_out:{client}",
        dedupe_seconds=HOUR,
    )


def token_expiring(name: str, role: str, expires_at: datetime) -> Alert:
    return Alert(
        "token_expiring",
        {
            "kind": "token_expiring",
            "text": (
                f"ZuesScan: the {role} token {name} expires on {expires_at:%Y-%m-%d %H:%M} UTC: "
                "rotate it (Settings → Tokens, or zues user rotate) before what uses it stops"
            ),
            "token": name,
            "expires_at": expires_at.isoformat(),
        },
        dedupe_key=f"token_expiring:{name}:{expires_at.isoformat()}",
        dedupe_seconds=DAY,
    )


def delivery_test(actor: str) -> Alert:
    return Alert(
        "test",
        {
            "kind": "test",
            "text": f"ZuesScan: a test alert, sent by {actor} from Settings. Delivery works.",
            "sent_by": actor,
        },
    )


def queue(config: ServiceConfig, alert: Alert) -> int | None:
    """Queue one alert outside a scan (not started, job failed, ...); its id, or None."""
    if not config.notify.webhook:
        return None
    try:
        with Storage(config.db) as store:
            return store.queue_alert(alert, stamp(now()))
    except (StorageError, sqlite3.Error) as exc:
        log.error("could not queue the %s alert: %s", alert.kind, exc)
        return None


def prune(config: ServiceConfig, at: datetime | None = None) -> int:
    """Delete the alerts older than `[notify] keep_days`; how many. Never raises."""
    if not Path(config.db).is_file():
        return 0
    before = (at or now()) - timedelta(days=config.notify.keep_days)
    try:
        with Storage(config.db) as store:
            deleted = store.prune_alerts(stamp(before))
    except (StorageError, sqlite3.Error) as exc:
        log.error("could not delete the old alerts: %s", exc)
        return 0
    if deleted:
        log.info("deleted %d alert(s) older than %d days", deleted, config.notify.keep_days)
    return deleted


# --- signing ------------------------------------------------------------------------------------


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify(
    secret: str,
    body: bytes,
    timestamp: str,
    signature: str,
    *,
    at: float | None = None,
    tolerance: int = TOLERANCE,
) -> bool:
    """A receiver's check: signed with `secret`, over these exact bytes, recently.
    `signature` may hold several (`sha256=..., sha256=...`, while the sender changes its
    secret): one made with `secret` is enough."""
    try:
        sent = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if at is None else at) - sent) > tolerance:
        return False  # too old (or from the future): possibly replayed
    expected = sign(secret, sent, body)
    found = [s.strip() for s in signature.split(",")][:MAX_SIGNATURES]
    return any(hmac.compare_digest(expected, s) for s in found)


MAX_SIGNATURES = 4  # a receiver looks at no more than this many in one header


def headers(row: Any, body: bytes, secrets: tuple[str, ...], at: datetime) -> dict[str, str]:
    """The headers of one delivery; signed with each of `secrets` (the current one first)."""
    sent = {
        "Content-Type": "application/json",
        "User-Agent": f"zues-scan/{__version__}",
        "X-ZuesScan-Delivery": str(row["id"]),
        "X-ZuesScan-Event": str(row["kind"]),
    }
    if secrets:
        timestamp = int(at.timestamp())
        sent["X-ZuesScan-Timestamp"] = str(timestamp)
        sent["X-ZuesScan-Signature"] = ", ".join(sign(s, timestamp, body) for s in secrets)
    return sent


# --- delivery -----------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would turn the POST into a GET without its body: report it instead."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_post(url: str, body: bytes, sent_headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, data=body, method="POST", headers=sent_headers)
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=TIMEOUT) as response:
        response.read()


@dataclass(frozen=True, slots=True)
class Delivery:
    ok: bool
    error: str | None = None
    permanent: bool = False  # retrying cannot help (e.g. 404: the webhook is gone)
    retry_after: int | None = None  # seconds the receiver asked us to wait


def deliver(url: str, body: bytes, sent_headers: dict[str, str], post: Post | None) -> Delivery:
    try:
        (post or http_post)(url, body, sent_headers)
    except urllib.error.HTTPError as exc:
        exc.close()  # the response it holds: its socket goes now, not when collected
        code = exc.code
        retry_after = _seconds(exc.headers.get("Retry-After") if exc.headers else None)
        permanent = 300 <= code < 500 and code not in (408, 425, 429)
        return Delivery(False, f"HTTP {code} {exc.reason}", permanent, retry_after)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return Delivery(False, _short(f"{type(exc).__name__}: {exc}"))
    return Delivery(True)


def _seconds(value: str | None) -> int | None:
    if value is None or not value.strip().isdigit():
        return None  # an HTTP date is possible too; then the usual backoff applies
    return int(value.strip())


def backoff(attempts: int) -> timedelta:
    """How long to wait after the `attempts`-th failed delivery."""
    doublings = min(max(attempts - 1, 0), 16)  # capped: no huge numbers on a long outage
    return min(BACKOFF_FIRST * (1 << doublings), BACKOFF_MAX)


@dataclass
class FlushReport:
    sent: int = 0
    retrying: int = 0
    gave_up: int = 0


def flush(
    config: ServiceConfig,
    *,
    ids: list[int] | None = None,
    post: Post | None = None,
    limit: int = BATCH,
) -> FlushReport:
    """Send the alerts that are due (only `ids`, if given); never raises."""
    report = FlushReport()
    webhook = config.notify.webhook
    if not webhook or not Path(config.db).is_file():
        return report  # nowhere to send to (alerts wait), or nothing queued yet
    where = urlsplit(webhook).hostname or "the webhook"  # the URL itself is a secret
    try:
        with Storage(config.db) as store:
            at = now()
            rows = store.claim_alerts(
                at=stamp(at), lease_until=stamp(at + LEASE), limit=limit, ids=ids
            )
            for row in rows:
                _send(store, row, webhook, where, config.notify.secrets(), post, report)
    except (StorageError, sqlite3.Error) as exc:
        log.error("could not deliver the queued alerts: %s", exc)
    return report


def _send(
    store: Storage,
    row: sqlite3.Row,
    webhook: str,
    where: str,
    secrets: tuple[str, ...],
    post: Post | None,
    report: FlushReport,
) -> None:
    body = str(row["payload"]).encode("utf-8")
    outcome = deliver(webhook, body, headers(row, body, secrets, now()), post)
    done = now()
    attempts = int(row["attempts"]) + 1  # the claim counted this attempt
    if outcome.ok:
        store.alert_sent(row["id"], stamp(done))
        report.sent += 1
        log.info("alert #%d (%s) delivered to %s", row["id"], row["kind"], where)
        return
    error = outcome.error or "failed"
    raised = datetime.fromisoformat(row["created_at"])
    if outcome.permanent or done - raised >= GIVE_UP_AFTER:
        store.alert_failed(row["id"], error, retry_at=None, at=stamp(done))
        report.gave_up += 1
        log.error(
            "gave up delivering alert #%d (%s) to %s after %d attempt(s): %s",
            row["id"],
            row["kind"],
            where,
            attempts,
            error,
        )
        return
    wait = backoff(attempts)
    if outcome.retry_after is not None:
        wait = min(timedelta(seconds=outcome.retry_after), BACKOFF_MAX)
    store.alert_failed(row["id"], error, retry_at=stamp(done + wait), at=stamp(done))
    report.retrying += 1
    log.warning(
        "could not deliver alert #%d (%s) to %s (attempt %d): %s; next try in %s",
        row["id"],
        row["kind"],
        where,
        attempts,
        error,
        wait,
    )


def describe(row: Any) -> dict[str, Any]:
    """One alert for the dashboard / API: what, and where its delivery stands."""
    payload = json.loads(row["payload"])
    if row["sent_at"]:
        state = "sent"
    elif row["gave_up_at"]:
        state = "gave up"
    else:
        state = "waiting"
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "kind": row["kind"],
        "summary": str(payload.get("text", "")).splitlines()[0] if payload.get("text") else "",
        "run_id": row["run_id"],
        "state": state,
        "attempts": row["attempts"],
        "next_try_at": row["next_try_at"] if state == "waiting" else None,
        "last_error": row["last_error"],
        "sent_at": row["sent_at"],
        "gave_up_at": row["gave_up_at"],
    }
