"""The alerts' outbox: queued with the run, delivered with retries, signed (G23).

No Redis: the outbox is the database; delivery goes through `notify.flush`, with a fake
POST and a fake clock, and once through a real HTTP server on this machine.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from zues_scan.alerts import Alert, RunFacts
from zues_scan.orchestrator import RunStatus, ScanRun
from zues_scan.server import notify
from zues_scan.server.config import Notify, ServiceConfig
from zues_scan.storage import Storage

SECRET = "a-shared-secret-of-32-characters"
T0 = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.at = T0
        monkeypatch.setattr(notify, "now", lambda: self.at)

    def wait(self, **delta: float) -> None:
        self.at += timedelta(**delta)


class Receiver:
    """A webhook: what it got, and what it answers (an exception to raise, or None)."""

    def __init__(self) -> None:
        self.got: list[tuple[bytes, dict[str, str]]] = []
        self.answer: Exception | None = None

    def __call__(self, url: str, body: bytes, headers: dict[str, str]) -> None:
        self.got.append((body, headers))
        if self.answer is not None:
            raise self.answer


def config(tmp_path: Path, webhook: str | None = "https://hooks.example.com/T0/secret") -> Any:
    return ServiceConfig(
        path=str(tmp_path / "service.toml"),
        db=str(tmp_path / "zues.db"),
        notify=Notify(webhook=webhook, secret=SECRET),
    )


def maybe_queued(tmp_path: Path, *alerts: Alert, at: datetime = T0) -> list[int | None]:
    """Each alert's id, or None where the dedupe key held it back."""
    with Storage(tmp_path / "zues.db") as store:
        return [store.queue_alert(a, at.isoformat()) for a in alerts]


def queued(tmp_path: Path, *alerts: Alert, at: datetime = T0) -> list[int]:
    ids = maybe_queued(tmp_path, *alerts, at=at)
    assert None not in ids
    return [i for i in ids if i is not None]


def row(tmp_path: Path, alert_id: int) -> Any:
    with Storage(tmp_path / "zues.db") as store:
        return store.alert_rows(ids=[alert_id])[0]


def http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://h", code, "Nope", headers, None)


# --- signing ------------------------------------------------------------------------------------


def test_a_signed_alert_verifies_only_as_sent_and_while_fresh() -> None:
    body = '{"text": "Lỗ hổng"}'.encode()
    signature = notify.sign(SECRET, 1_800_000_000, body)

    assert signature.startswith("sha256=") and len(signature) == 7 + 64
    assert notify.verify(SECRET, body, "1800000000", signature, at=1_800_000_100)
    assert not notify.verify(SECRET, body + b" ", "1800000000", signature, at=1_800_000_100)
    assert not notify.verify(
        "another-secret-xxxxxxxx", body, "1800000000", signature, at=1_800_000_100
    )
    assert not notify.verify(SECRET, body, "1800000001", signature, at=1_800_000_100)
    assert not notify.verify(SECRET, body, "1800000000", signature, at=1_800_000_301)  # replayed
    assert not notify.verify(SECRET, body, "soon", signature)


def test_backoff_doubles_up_to_an_hour() -> None:
    minutes = [notify.backoff(n).total_seconds() / 60 for n in range(1, 10)]
    assert minutes == [1, 2, 4, 8, 16, 32, 60, 60, 60]
    assert notify.backoff(10_000) == timedelta(hours=1)  # no overflow on a long outage


# --- delivery -----------------------------------------------------------------------------------


def test_a_delivered_alert_carries_its_id_kind_and_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Clock(monkeypatch)
    (alert_id,) = queued(tmp_path, notify.delivery_test("root"))
    receiver = Receiver()

    report = notify.flush(config(tmp_path), post=receiver)

    assert (report.sent, report.retrying, report.gave_up) == (1, 0, 0)
    [(body, headers)] = receiver.got
    assert json.loads(body)["kind"] == "test"
    assert headers["X-ZuesScan-Delivery"] == str(alert_id)
    assert headers["X-ZuesScan-Event"] == "test"
    assert headers["X-ZuesScan-Timestamp"] == str(int(T0.timestamp()))
    assert notify.verify(
        SECRET,
        body,
        headers["X-ZuesScan-Timestamp"],
        headers["X-ZuesScan-Signature"],
        at=T0.timestamp(),
    )
    assert row(tmp_path, alert_id)["sent_at"] == "2026-11-24T09:00:00+00:00"
    assert notify.flush(config(tmp_path), post=receiver).sent == 0  # sent once


def test_a_failed_delivery_is_retried_later_and_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock(monkeypatch)
    (alert_id,) = queued(tmp_path, notify.delivery_test("root"))
    receiver = Receiver()
    receiver.answer = ConnectionRefusedError("refused")

    assert notify.flush(config(tmp_path), post=receiver).retrying == 1
    first = row(tmp_path, alert_id)
    assert (first["attempts"], first["next_try_at"]) == (1, "2026-11-24T09:01:00+00:00")
    assert "ConnectionRefusedError: refused" in first["last_error"]

    clock.wait(seconds=59)
    assert notify.flush(config(tmp_path), post=receiver).retrying == 0  # not due yet
    clock.wait(seconds=1)
    notify.flush(config(tmp_path), post=receiver)
    assert row(tmp_path, alert_id)["next_try_at"] == "2026-11-24T09:03:00+00:00"  # +2 min

    receiver.answer = None
    clock.wait(minutes=2)
    assert notify.flush(config(tmp_path), post=receiver).sent == 1
    done = row(tmp_path, alert_id)
    assert (done["attempts"], done["last_error"]) == (3, None)
    assert len(receiver.got) == 3


def test_an_alert_is_given_up_after_a_day(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock(monkeypatch)
    (alert_id,) = queued(tmp_path, notify.delivery_test("root"))
    receiver = Receiver()
    receiver.answer = TimeoutError("timed out")
    notify.flush(config(tmp_path), post=receiver)

    clock.wait(hours=24)
    with caplog.at_level(logging.ERROR, logger="zues_scan.server.notify"):
        assert notify.flush(config(tmp_path), post=receiver).gave_up == 1

    assert row(tmp_path, alert_id)["gave_up_at"] == "2026-11-25T09:00:00+00:00"
    assert "gave up delivering alert" in caplog.text and "secret" not in caplog.text
    clock.wait(hours=1)
    assert notify.flush(config(tmp_path), post=receiver).retrying == 0  # over


def test_an_answer_retrying_cannot_change_gives_up_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Clock(monkeypatch)
    gone, moved = queued(tmp_path, notify.delivery_test("a"), notify.delivery_test("b"))
    receiver = Receiver()
    receiver.answer = http_error(404)  # the webhook was deleted

    notify.flush(config(tmp_path), post=receiver, ids=[gone])
    receiver.answer = http_error(302)  # a redirect would drop the POST's body
    notify.flush(config(tmp_path), post=receiver, ids=[moved])

    assert (
        row(tmp_path, gone)["gave_up_at"] and row(tmp_path, gone)["last_error"] == "HTTP 404 Nope"
    )
    assert row(tmp_path, moved)["gave_up_at"]


def test_retry_after_is_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    Clock(monkeypatch)
    (alert_id,) = queued(tmp_path, notify.delivery_test("root"))
    receiver = Receiver()
    receiver.answer = http_error(429, retry_after="300")

    notify.flush(config(tmp_path), post=receiver)

    assert row(tmp_path, alert_id)["next_try_at"] == "2026-11-24T09:05:00+00:00"


def test_without_a_webhook_alerts_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    Clock(monkeypatch)
    (alert_id,) = queued(tmp_path, notify.delivery_test("root"))
    receiver = Receiver()

    assert notify.flush(config(tmp_path, webhook=None), post=receiver).sent == 0

    assert receiver.got == [] and row(tmp_path, alert_id)["attempts"] == 0


def test_an_alert_being_sent_is_not_taken_by_another_sender(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Clock(monkeypatch)
    queued(tmp_path, notify.delivery_test("root"))
    with Storage(tmp_path / "zues.db") as store:  # another process claims it first
        (claimed,) = store.claim_alerts(
            at=notify.stamp(T0), lease_until=notify.stamp(T0 + notify.LEASE), limit=5
        )
    receiver = Receiver()

    assert notify.flush(config(tmp_path), post=receiver).sent == 0
    assert receiver.got == []


def test_a_lasting_condition_alerts_once_per_window(tmp_path: Path) -> None:
    alert = notify.not_started("lab", "refused: the authorisation expired on 2026-11-01")
    first, again = maybe_queued(tmp_path, alert, alert)
    (later,) = maybe_queued(tmp_path, alert, at=T0 + timedelta(days=1, seconds=1))
    (other,) = maybe_queued(
        tmp_path, notify.not_started("dmz", "refused: the authorisation expired")
    )

    assert first is not None and again is None and later is not None and other is not None


# --- how long alerts are kept -------------------------------------------------------------------


def test_old_alerts_are_deleted_and_the_rest_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock(monkeypatch)
    sent, failed, _waiting = queued(
        tmp_path, *(notify.delivery_test(n) for n in ("sent", "failed", "waiting"))
    )
    receiver = Receiver()
    notify.flush(config(tmp_path), post=receiver, ids=[sent])
    receiver.answer = http_error(404)
    notify.flush(config(tmp_path), post=receiver, ids=[failed])
    clock.wait(days=10)
    (recent,) = queued(tmp_path, notify.delivery_test("recent"), at=clock.at)
    keep = ServiceConfig(
        path=str(tmp_path / "service.toml"),
        db=str(tmp_path / "zues.db"),
        notify=Notify(keep_days=10),
    )

    clock.wait(seconds=-1)  # 10 days to the second: not yet
    assert notify.prune(keep) == 0
    clock.wait(seconds=1)
    # Sent or given up 10 days ago, and never delivered (no webhook) since then: gone.
    assert notify.prune(keep) == 3
    with Storage(tmp_path / "zues.db") as store:
        assert [r["id"] for r in store.alert_rows()] == [recent]


def test_pruning_never_lets_an_alert_repeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The shortest keep (7 days) is longer than any alert's deduplication window (a day).
    clock = Clock(monkeypatch)
    alert = notify.not_started("lab", "refused: the authorisation expired")
    (first,) = queued(tmp_path, alert)
    notify.flush(config(tmp_path), post=Receiver())
    clock.wait(hours=23)
    shortest = ServiceConfig(
        path=str(tmp_path / "service.toml"),
        db=str(tmp_path / "zues.db"),
        notify=Notify(keep_days=7),
    )
    assert notify.prune(shortest) == 0
    assert maybe_queued(tmp_path, alert, at=clock.at) == [None]  # still held back


def test_without_a_database_there_is_nothing_to_prune(tmp_path: Path) -> None:
    assert notify.prune(config(tmp_path)) == 0
    assert not (tmp_path / "zues.db").exists()


# --- queued with the run ------------------------------------------------------------------------


def a_run(status: RunStatus = RunStatus.COMPLETED) -> ScanRun:
    return ScanRun(
        target="scanme.lab",
        started_at="2026-11-24T09:00:00+00:00",
        finished_at="2026-11-24T09:01:00+00:00",
        status=status,
        profile="quick",
    )


def test_a_runs_alerts_are_saved_with_it(tmp_path: Path) -> None:
    seen: list[RunFacts] = []

    def policy(facts: RunFacts) -> list[Alert]:
        seen.append(facts)
        return [Alert("run", {"text": f"run #{facts.run_id}"})]

    with Storage(tmp_path / "zues.db") as store:
        store.save_run(a_run(RunStatus.FAILED))
        run_id = store.save_run(a_run(), alerts=policy)
        (alert,) = store.alert_rows()

    assert (alert["run_id"], alert["kind"], json.loads(alert["payload"])) == (
        run_id,
        "run",
        {"text": f"run #{run_id}"},
    )
    assert alert["created_at"] == "2026-11-24T09:01:00+00:00"  # the run's end, in UTC
    assert seen[0].failed_before == 1  # the failed run just before this one


def test_a_broken_alert_policy_never_loses_the_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(facts: RunFacts) -> list[Alert]:
        return [Alert("run", {"not json": object()})]

    with caplog.at_level(logging.ERROR, logger="zues_scan.storage"):
        with Storage(tmp_path / "zues.db") as store:
            run_id = store.save_run(a_run(), alerts=broken)
            assert store.load_run(run_id) is not None
            assert store.alert_rows() == []
    assert "the run is saved" in caplog.text


# --- through a real HTTP server -----------------------------------------------------------------


@pytest.fixture
def server() -> Iterator[tuple[str, list[tuple[str, bytes, dict[str, str]]]]]:
    got: list[tuple[str, bytes, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - the http.server API
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append((self.path, body, dict(self.headers)))
            if self.path == "/moved":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
            else:
                self.send_response(204)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", got
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_delivery_over_http(
    tmp_path: Path, server: tuple[str, list[tuple[str, bytes, dict[str, str]]]]
) -> None:
    base, got = server
    test = notify.delivery_test("root")
    ok, moved = queued(tmp_path, test, test, at=datetime.now(UTC))  # the real clock here

    assert notify.flush(config(tmp_path, webhook=f"{base}/hook"), ids=[ok]).sent == 1
    report = notify.flush(config(tmp_path, webhook=f"{base}/moved"), ids=[moved])

    [(path, body, headers), (moved_path, _, _)] = got
    assert path == "/hook" and moved_path == "/moved"  # the redirect was not followed
    assert headers["Content-Type"] == "application/json"
    assert headers["User-Agent"].startswith("zues-scan/")
    assert notify.verify(
        SECRET, body, headers["X-Zuesscan-Timestamp"], headers["X-Zuesscan-Signature"]
    )
    assert report.gave_up == 1 and "HTTP 302" in row(tmp_path, moved)["last_error"]


def test_a_token_about_to_expire_raises_an_alert_once_a_day(tmp_path: Path) -> None:
    pytest.importorskip("rq")
    from dataclasses import replace

    from zues_scan.server import scheduler
    from zues_scan.server.config import Token

    soon = Token("ci", "0" * 64, "viewer", expires_at=T0 + timedelta(days=3))
    later = Token("siem", "1" * 64, "viewer", expires_at=T0 + timedelta(days=30))
    service = replace(config(tmp_path), tokens=(soon, later))
    with Storage(tmp_path / "zues.db"):
        pass

    assert scheduler.warn_expiring_tokens(service, now=T0) == ["ci"]
    scheduler.warn_expiring_tokens(service, now=T0)  # the next round: held back

    with Storage(tmp_path / "zues.db") as store:
        (alert,) = store.alert_rows()
    assert alert["kind"] == "token_expiring"
    assert "the viewer token ci expires on 2026-11-27 09:00 UTC" in alert["payload"]
