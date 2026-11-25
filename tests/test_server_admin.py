"""The admin API: scopes, targets and tokens edited in the dashboard, end to end."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("fakeredis")

from fastapi.testclient import TestClient  # noqa: E402
from test_server_web import ALICE, BOB, TOKENS, App, _lab, config_text, sha  # noqa: E402,F401

from zues_scan.storage import Storage  # noqa: E402

ROOT = "root-admin-token-0123456789abcdefghijklmnopq"
ADMIN = f'[[tokens]]\nname = "root"\nsha256 = "{sha(ROOT)}"\nrole = "admin"\n\n'
SCOPE = "@engagement LAB-2\nscanme.lab\n10.0.0.0/24\n"


@pytest.fixture
def svc(tmp_path: Path) -> App:
    app = App(tmp_path)
    app.rewrite(config_text(tmp_path.as_posix(), TOKENS + ADMIN))
    return app


def test_only_admins_see_or_change_the_settings(svc: App) -> None:
    for token in (ALICE, BOB):  # operator, viewer
        client = svc.client(token)
        assert client.get("/api/v1/admin/config").status_code == 403
        assert client.put("/api/v1/admin/scopes/x", json={"text": SCOPE}).status_code == 403
        assert (
            client.post("/api/v1/admin/tokens", json={"name": "x", "role": "admin"}).status_code
            == 403
        )
    settings = svc.client(ROOT).get("/api/v1/admin/config").json()
    assert {t["name"]: t["source"] for t in settings["targets"]} == {"dmz": "file", "lab": "file"}
    assert {p["name"] for p in settings["plugins"]} >= {"nmap", "naabu", "httpx", "nuclei"}
    assert [s["source"] for s in settings["scopes"]] == ["file"]  # a path, not its content
    assert "text" not in settings["scopes"][0]


def test_an_admin_adds_a_target_and_an_operator_scans_it(svc: App) -> None:
    root = svc.client(ROOT)
    saved = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    assert saved.status_code == 200, saved.text
    target = {"target": "scanme.lab", "scope": "lab2", "profile": "quick", "every": "12h"}
    saved = root.put("/api/v1/admin/targets/web", json=target)
    assert saved.status_code == 200, saved.text

    settings = root.get("/api/v1/admin/config").json()
    (scope,) = [s for s in settings["scopes"] if s["source"] == "dashboard"]
    assert (scope["name"], scope["used_by"], scope["engagement"]) == ("lab2", ["web"], "LAB-2")
    listed = {t["name"]: t for t in svc.client(BOB).get("/api/v1/targets").json()}
    assert listed["web"]["source"] == "dashboard" and listed["web"]["every_seconds"] == 12 * 3600

    queued = svc.client(ALICE).post("/api/v1/scans", json={"target": "web"})
    assert queued.status_code == 202, queued.text
    svc.work()
    with Storage(svc.db) as store:
        run_id = store.latest_run_id()
        assert run_id is not None
        run = store.load_run(run_id)
        events = [e for _, e, _ in store.audit_events()]
    assert run is not None and run.target == "scanme.lab"
    assert run.operator == "alice"
    assert run.scope_path == "dashboard scope lab2"  # the run says which scope authorised it
    assert next(e for e in events if e.kind == "scan").scope_sha256 == run.scope_sha256
    assert [e.target for e in events if e.kind == "config"] == ["scope:lab2", "target:web"]
    assert all(e.operator == "root" for e in events if e.kind == "config")


def test_mistakes_are_refused_with_the_reason(svc: App) -> None:
    root = svc.client(ROOT)
    bad = root.put("/api/v1/admin/scopes/lab2", json={"text": "10.0.0.0/24\nnot a host!\n"})
    assert bad.status_code == 422 and "scope lab2:2" in bad.json()["detail"]
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    outside = root.put("/api/v1/admin/targets/web", json={"target": "8.8.8.8", "scope": "lab2"})
    assert outside.status_code == 422 and "outside the authorised scope" in outside.json()["detail"]
    active = {"target": "10.0.0.5", "scope": "lab2", "checks": ["nuclei"]}
    refused = root.put("/api/v1/admin/targets/web", json=active)
    assert refused.status_code == 422 and "@activity active" in refused.json()["detail"]
    paths = {"target": "10.0.0.5", "scope": "lab2", "credentials": "/etc/shadow"}
    assert root.put("/api/v1/admin/targets/web", json=paths).status_code == 422  # no server paths
    owned = root.put("/api/v1/admin/targets/lab", json={"target": "10.0.0.5", "scope": "lab2"})
    assert owned.status_code == 422 and "service.toml" in owned.json()["detail"]
    assert root.delete("/api/v1/admin/targets/nope").status_code == 404
    root.put("/api/v1/admin/targets/web", json={"target": "10.0.0.5", "scope": "lab2"})
    used = root.delete("/api/v1/admin/scopes/lab2")
    assert used.status_code == 422 and "used by web" in used.json()["detail"]
    assert root.delete("/api/v1/admin/targets/web").status_code == 204
    assert root.delete("/api/v1/admin/scopes/lab2").status_code == 204


def test_a_new_token_works_at_once_and_a_revoked_one_stops(svc: App) -> None:
    root = svc.client(ROOT)
    made = root.post("/api/v1/admin/tokens", json={"name": "carol", "role": "operator"})
    assert made.status_code == 201, made.text
    token = made.json()["token"]
    me = svc.client(token).get("/api/v1/me").json()
    assert (me["name"], me["role"]) == ("carol", "operator")
    listed = {t["name"]: t for t in root.get("/api/v1/admin/config").json()["tokens"]}
    assert listed["carol"]["source"] == "dashboard" and listed["root"]["you"]
    assert "token" not in listed["carol"] and "sha256" not in listed["carol"]
    assert root.delete("/api/v1/admin/tokens/carol").status_code == 204
    assert svc.client(token).get("/api/v1/me").status_code == 401
    assert root.delete("/api/v1/admin/tokens/root").status_code == 404  # service.toml's own


def test_a_session_needs_the_csrf_header_to_change_settings(svc: App) -> None:
    browser = svc.client()
    assert browser.post("/api/v1/session", json={"token": ROOT}).status_code == 200
    blocked = browser.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    assert blocked.status_code == 403
    allowed = browser.put(
        "/api/v1/admin/scopes/lab2", json={"text": SCOPE}, headers={"X-ZuesScan": "1"}
    )
    assert allowed.status_code == 200


def test_the_dashboard_has_a_settings_page_for_admins(svc: App) -> None:
    page = svc.client().get("/").text
    assert 'data-view="settings" hidden' in page  # shown by app.js to admins only
    script = svc.client().get("/static/app.js").text
    assert "settings: settings" in script and '"/admin/config"' in script
    # The name pattern compiles in browsers' "v" mode: "-" escaped in the class.
    assert r'var NAME_PATTERN = "[a-z0-9][a-z0-9_\\-]*";' in script


def test_an_admin_sees_who_is_signed_in_and_ends_a_session(svc: App) -> None:
    from test_server_web import CSRF, sign_in

    root = sign_in(svc, ROOT)
    bob = sign_in(svc, BOB, client=("192.0.2.44", 1))
    assert svc.client(ALICE).get("/api/v1/admin/sessions").status_code == 403

    listed = root.get("/api/v1/admin/sessions").json()
    assert [(s["name"], s["role"], s["client"], s["you"]) for s in listed] == [
        ("root", "admin", "testclient", True),
        ("bob", "viewer", "192.0.2.44", False),
    ]
    assert listed == root.get("/api/v1/admin/config").json()["sessions"]
    assert not {"secret_sha256", "token_sha256"} & set(listed[0])

    bob_id = listed[1]["id"]
    assert root.delete(f"/api/v1/admin/sessions/{bob_id}").status_code == 403  # CSRF
    assert root.delete(f"/api/v1/admin/sessions/{bob_id}", headers=CSRF).status_code == 204
    assert bob.get("/api/v1/me").status_code == 401
    assert root.delete(f"/api/v1/admin/sessions/{bob_id}", headers=CSRF).status_code == 404
    with Storage(svc.db) as store:
        last = store.audit_events()[-1][1]
    assert (last.kind, last.target, last.operator, last.detail["action"]) == (
        "auth",
        "token:bob",
        "root",
        "session ended",
    )


def test_revoking_a_dashboard_token_ends_its_sessions(svc: App) -> None:
    from test_server_web import CSRF, sign_in

    root = svc.client(ROOT)
    made = root.post("/api/v1/admin/tokens", json={"name": "carol", "role": "viewer"}).json()
    carol = sign_in(svc, made["token"])
    assert carol.get("/api/v1/me").status_code == 200

    assert root.delete("/api/v1/admin/tokens/carol").status_code == 204

    assert carol.get("/api/v1/me").status_code == 401
    assert [s["name"] for s in root.get("/api/v1/admin/sessions").json()] == []
    assert carol.delete("/api/v1/session", headers=CSRF).status_code == 204


NOTIFY = (
    '\n[notify]\nwebhook = "https://hooks.example.com/T9/secret"\nsecret = "0123456789abcdef0123"\n'
)


@pytest.fixture
def posts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    sent: list[dict[str, str]] = []

    def post(url: str, body: bytes, headers: dict[str, str]) -> None:
        sent.append(headers)
        if len(sent) == 1:
            raise ConnectionRefusedError("refused")  # the first try fails

    monkeypatch.setattr("zues_scan.server.notify.http_post", post)
    return sent


def test_an_admin_tests_the_webhook_and_retries_an_alert(
    svc: App, posts: list[dict[str, str]]
) -> None:
    from test_server_web import CSRF, sign_in

    root = sign_in(svc, ROOT)
    assert root.post("/api/v1/admin/alerts/test", headers=CSRF).status_code == 409  # none yet
    svc.rewrite(config_text(svc.dir.as_posix(), TOKENS + ADMIN) + NOTIFY)
    assert svc.client(ALICE).post("/api/v1/admin/alerts/test").status_code == 403

    failed = root.post("/api/v1/admin/alerts/test", headers=CSRF).json()
    assert (failed["kind"], failed["state"], failed["attempts"]) == ("test", "waiting", 1)
    assert "refused" in failed["last_error"]
    retried = root.post(f"/api/v1/admin/alerts/{failed['id']}/retry", headers=CSRF).json()
    assert (retried["state"], retried["attempts"], retried["last_error"]) == ("sent", 2, None)
    assert posts[1]["X-ZuesScan-Signature"].startswith("sha256=")
    assert root.post(f"/api/v1/admin/alerts/{failed['id']}/retry", headers=CSRF).status_code == 404

    alerts = root.get("/api/v1/admin/config").json()["alerts"]
    assert (alerts["webhook"], alerts["signed"], alerts["failed_scans"]) == (
        "hooks.example.com",  # only its host: the URL is a secret
        True,
        3,
    )
    assert [a["summary"] for a in alerts["latest"]] == [
        "ZuesScan: a test alert, sent by root from Settings. Delivery works."
    ]
    assert "T9" not in root.get("/api/v1/admin/alerts").text


def test_a_lock_out_raises_one_alert_an_hour(svc: App, posts: list[dict[str, str]]) -> None:
    from fastapi.testclient import TestClient

    from zues_scan.server import sessions

    svc.rewrite(config_text(svc.dir.as_posix(), TOKENS + ADMIN) + NOTIFY)
    attacker = TestClient(svc.app, client=("203.0.113.66", 1))
    for _ in range(sessions.LIMIT):
        attacker.post("/api/v1/session", json={"token": "guess"})
    svc.app.state.throttle = sessions.Throttle()  # as if the lock had expired
    svc.redis.flushall()
    for _ in range(sessions.LIMIT):
        attacker.post("/api/v1/session", json={"token": "guess"})

    with Storage(svc.db) as store:
        (alert,) = store.alert_rows()  # the second lock-out within the hour: held back
        locks = [e for _, e, _ in store.audit_events() if e.detail.get("action") == "locked out"]
    assert alert["kind"] == "locked_out" and len(locks) == 2
    assert "203.0.113.66 was locked out of the dashboard" in alert["payload"]
    assert posts == []  # the web does not post it: the scheduler's next round does


def test_a_dashboard_target_can_run_on_a_cron_schedule(svc: App) -> None:
    root = svc.client(ROOT)
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).status_code == 200
    target = {"target": "scanme.lab", "scope": "lab2", "cron": "30 1 * * mon-fri +07:00"}

    assert root.put("/api/v1/admin/targets/weekdays", json=target).status_code == 200
    both = {**target, "every": "12h"}
    refused = root.put("/api/v1/admin/targets/weekdays", json=both)
    assert refused.status_code == 422 and "every or cron, not both" in refused.json()["detail"]
    too_often = {**target, "cron": "*/2 * * * *"}
    assert root.put("/api/v1/admin/targets/w2", json=too_often).status_code == 422

    listed = {t["name"]: t for t in svc.client(BOB).get("/api/v1/targets").json()}
    assert listed["weekdays"]["cron"] == "30 1 * * mon-fri +07:00"
    assert listed["weekdays"]["every_seconds"] is None
    settings = {t["name"]: t for t in root.get("/api/v1/admin/config").json()["targets"]}
    assert settings["weekdays"]["cron"] == "30 1 * * mon-fri +07:00"


def test_tokens_expire_and_are_rotated(svc: App) -> None:
    from datetime import UTC, datetime, timedelta

    from test_server_web import CSRF, sign_in

    root = svc.client(ROOT)
    made = root.post(
        "/api/v1/admin/tokens", json={"name": "ci", "role": "viewer", "valid_days": 30}
    )
    forever = root.post(
        "/api/v1/admin/tokens", json={"name": "siem", "role": "viewer", "valid_days": None}
    )
    assert made.status_code == forever.status_code == 201
    listed = {t["name"]: t for t in root.get("/api/v1/admin/config").json()["tokens"]}
    expires = datetime.fromisoformat(listed["ci"]["expires_at"])
    assert abs(expires - (datetime.now(UTC) + timedelta(days=30))) < timedelta(minutes=1)
    assert listed["siem"]["expires_at"] is None and listed["root"]["expires_at"] is None
    too_long = {"name": "x", "role": "viewer", "valid_days": 3650}
    assert root.post("/api/v1/admin/tokens", json=too_long).status_code == 422

    old = made.json()["token"]
    browser = sign_in(svc, old)
    assert svc.client(ALICE).post("/api/v1/admin/tokens/ci/rotate", json={}).status_code == 403
    rotated = root.post("/api/v1/admin/tokens/ci/rotate", json={"valid_days": 90}).json()

    assert svc.client(old).get("/api/v1/me").status_code == 401  # the old value: over
    assert browser.get("/api/v1/me").status_code == 401  # and its session
    assert svc.client(rotated["token"]).get("/api/v1/me").json()["name"] == "ci"
    assert root.post("/api/v1/admin/tokens/root/rotate", json={}).status_code == 404  # a file's
    with Storage(svc.db) as store:
        actions = [e.detail["action"] for _, e, _ in store.audit_events() if e.target == "token:ci"]
    assert actions == ["token created", "signed in", "token rotated"]
    assert rotated["token"] not in repr(actions) and old not in repr(actions)
    assert browser.delete("/api/v1/session", headers=CSRF).status_code == 204


def test_an_expired_token_is_refused_plainly_and_is_not_a_guess(svc: App) -> None:
    from fastapi.testclient import TestClient

    from zues_scan.server import sessions

    expired = (
        TOKENS
        + ADMIN
        + '[[tokens]]\nname = "old"\nsha256 = "'
        + sha("old-token-0123456789abcdef")
        + '"\nrole = "viewer"\nexpires = 2020-01-31\n\n'
    )
    svc.rewrite(config_text(svc.dir.as_posix(), expired))
    holder = TestClient(svc.app, client=("192.0.2.80", 1))

    for _ in range(sessions.LIMIT + 2):
        refused = holder.get(
            "/api/v1/me", headers={"Authorization": "Bearer old-token-0123456789abcdef"}
        )
        assert refused.status_code == 401  # never 429: whoever has it is not guessing
    assert "expired on 2020-02-01 00:00 UTC" in refused.json()["detail"]
    login = holder.post("/api/v1/session", json={"token": "old-token-0123456789abcdef"})
    assert login.status_code == 401 and "expired" in login.json()["detail"]


def test_a_session_ends_when_its_token_expires(svc: App, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime, timedelta

    from test_server_web import sign_in

    from zues_scan.server import sessions

    made = svc.client(ROOT).post(
        "/api/v1/admin/tokens", json={"name": "short", "role": "viewer", "valid_days": 1}
    )
    browser = sign_in(svc, made.json()["token"])
    assert browser.get("/api/v1/me").status_code == 200

    later = datetime.now(UTC) + timedelta(days=1, minutes=1)
    monkeypatch.setattr(sessions, "now", lambda: later)

    assert browser.get("/api/v1/me").status_code == 401


def test_every_settings_change_raises_an_alert_with_its_audit_event(svc: App) -> None:
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/before", json={"text": SCOPE})  # no webhook yet: nothing
    with Storage(svc.db) as store:
        assert store.alert_rows() == []
    svc.rewrite(config_text(svc.dir.as_posix(), TOKENS + ADMIN) + NOTIFY)

    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    root.put("/api/v1/admin/targets/web", json={"target": "scanme.lab", "scope": "lab2"})
    made = root.post("/api/v1/admin/tokens", json={"name": "carol", "role": "admin"}).json()
    root.post("/api/v1/admin/tokens/carol/rotate", json={})
    root.delete("/api/v1/admin/targets/web")

    with Storage(svc.db) as store:
        rows = list(reversed(store.alert_rows()))
    texts = [json.loads(r["payload"])["text"] for r in rows]
    assert [r["kind"] for r in rows] == ["config_changed"] * 5
    assert texts == [
        "ZuesScan: root: scope saved — scope lab2: what may be scanned changed; see the audit "
        "trail",
        "ZuesScan: root: target added — target web: what is scanned, how or when changed; see "
        "the audit trail",
        "ZuesScan: root: token created — token carol (role admin): who may use ZuesScan changed; "
        "see the audit trail",
        "ZuesScan: root: token rotated — token carol: who may use ZuesScan changed; see the audit "
        "trail",
        "ZuesScan: root: target deleted — target web: what is scanned, how or when changed; see "
        "the audit trail",
    ]
    assert made["token"] not in repr(rows) and sha(made["token"]) not in repr(rows)


# --- two people for a scope change (G30) ---------------------------------------------------------


def with_approval(svc: App, on: bool = True, extra: str = "") -> None:
    text = config_text(svc.dir.as_posix(), TOKENS + ADMIN) + extra
    if on:
        text = text.replace('queue = "web"\n', 'queue = "web"\nscope_approval = true\n', 1)
    svc.rewrite(text)


def admin_token(svc: App, name: str) -> str:
    made = svc.client(ROOT).post("/api/v1/admin/tokens", json={"name": name, "role": "admin"})
    assert made.status_code == 201, made.text
    return str(made.json()["token"])


def rotated_admin(svc: App, name: str) -> TestClient:
    """A second admin who rotated the token root made, so that only they know it."""
    first = svc.client(admin_token(svc, name))
    value = first.post(f"/api/v1/admin/tokens/{name}/rotate", json={}).json()["token"]
    return svc.client(value)


def test_with_approval_a_scope_change_waits_for_a_second_admin(svc: App) -> None:
    with_approval(svc)
    carol = admin_token(svc, "carol")  # made by root: root has seen its value
    root = svc.client(ROOT)

    proposed = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE, "reason": "PT-9 signed"})
    assert proposed.status_code == 202, proposed.text
    pid = proposed.json()["proposal"]
    settings = root.get("/api/v1/admin/config").json()
    assert settings["scope_approval"] is True
    assert [s["name"] for s in settings["scopes"] if s["source"] == "dashboard"] == []  # not yet
    (pending,) = settings["proposals"]
    assert (pending["id"], pending["proposed_by"], pending["reason"]) == (
        pid,
        "root",
        "PT-9 signed",
    )
    assert pending["can"] == {"approve": False, "reject": False, "withdraw": True}

    own = root.post(f"/api/v1/admin/proposals/{pid}/approve", json={})
    assert own.status_code == 403 and "second admin" in own.json()["detail"]
    issued = svc.client(carol).post(f"/api/v1/admin/proposals/{pid}/approve", json={})
    assert issued.status_code == 403 and "rotate your own token" in issued.json()["detail"]

    rotated = svc.client(carol).post("/api/v1/admin/tokens/carol/rotate", json={})
    approved = svc.client(rotated.json()["token"]).post(
        f"/api/v1/admin/proposals/{pid}/approve", json={}
    )

    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    scopes = root.get("/api/v1/admin/config").json()["scopes"]
    assert [s["name"] for s in scopes if s["source"] == "dashboard"] == ["lab2"]
    with Storage(svc.db) as store:
        events = [e for _, e, _ in store.audit_events() if e.target == "scope:lab2"]
    assert [(e.operator, e.detail["action"]) for e in events] == [
        ("root", "scope change proposed"),
        ("carol", "scope saved"),
    ]
    assert (events[1].detail["proposed_by"], events[1].detail["approved_by"]) == ("root", "carol")


def test_a_chain_of_issued_tokens_cannot_approve_for_its_origin(svc: App) -> None:
    with_approval(svc)
    carol = svc.client(admin_token(svc, "carol"))  # root -> carol
    dave = carol.post("/api/v1/admin/tokens", json={"name": "dave", "role": "admin"})
    root = svc.client(ROOT)
    pid = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).json()["proposal"]

    # dave's value was issued by carol, whose value root has seen: root could be dave.
    refused = svc.client(dave.json()["token"]).post(f"/api/v1/admin/proposals/{pid}/approve")
    assert refused.status_code == 403


def test_a_proposal_against_an_older_scope_is_not_approved(svc: App) -> None:
    with_approval(svc)
    carol = rotated_admin(svc, "carol")
    root = svc.client(ROOT)
    pid = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).json()["proposal"]
    with_approval(svc, on=False)  # the server's operator turns approval off for a moment
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE + "10.0.1.0/24\n"}).is_success
    with_approval(svc)

    stale = carol.post(f"/api/v1/admin/proposals/{pid}/approve", json={})

    assert stale.status_code == 409 and "changed since" in stale.json()["detail"]
    (row,) = root.get("/api/v1/admin/proposals", params={"all": True}).json()
    assert row["status"] == "superseded"


def test_reject_needs_a_reason_and_only_the_proposer_withdraws(svc: App) -> None:
    with_approval(svc)
    carol = svc.client(admin_token(svc, "carol"))
    root = svc.client(ROOT)
    first = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).json()["proposal"]

    assert carol.post(f"/api/v1/admin/proposals/{first}/reject", json={}).status_code == 422
    assert carol.post(f"/api/v1/admin/proposals/{first}/withdraw", json={}).status_code == 403
    rejected = carol.post(
        f"/api/v1/admin/proposals/{first}/reject", json={"note": "no signed authorisation yet"}
    )
    assert rejected.json()["status"] == "rejected"
    again = carol.post(f"/api/v1/admin/proposals/{first}/reject", json={"note": "x"})
    assert again.status_code == 409  # decided already

    second = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).json()["proposal"]
    third = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE + "#v3\n"}).json()
    statuses = {
        p["id"]: p["status"]
        for p in root.get("/api/v1/admin/proposals", params={"all": True}).json()
    }
    assert statuses[second] == "superseded" and statuses[third["proposal"]] == "pending"
    withdrawn = root.post(f"/api/v1/admin/proposals/{third['proposal']}/withdraw", json={})
    assert withdrawn.json()["status"] == "withdrawn"
    assert root.get("/api/v1/admin/proposals").json() == []


def test_deleting_a_scope_is_a_proposal_too(svc: App) -> None:
    with_approval(svc, on=False)
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    root.put("/api/v1/admin/targets/web", json={"target": "scanme.lab", "scope": "lab2"})
    with_approval(svc)
    carol = rotated_admin(svc, "carol")

    in_use = root.delete("/api/v1/admin/scopes/lab2")
    assert in_use.status_code == 422 and "used by web" in in_use.json()["detail"]
    root.delete("/api/v1/admin/targets/web")
    proposed = root.delete("/api/v1/admin/scopes/lab2", params={"reason": "engagement over"})
    assert proposed.status_code == 202
    pid = proposed.json()["proposal"]
    assert any(s["name"] == "lab2" for s in root.get("/api/v1/admin/config").json()["scopes"])

    assert carol.post(f"/api/v1/admin/proposals/{pid}/approve", json={}).status_code == 200
    scopes = root.get("/api/v1/admin/config").json()["scopes"]
    assert not any(s["name"] == "lab2" for s in scopes)


def test_each_step_of_a_proposal_is_announced(svc: App) -> None:
    with_approval(svc, extra=NOTIFY)
    carol = svc.client(admin_token(svc, "carol"))
    root = svc.client(ROOT)
    pid = root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).json()["proposal"]
    carol.post(f"/api/v1/admin/proposals/{pid}/reject", json={"note": "not signed"})

    with Storage(svc.db) as store:
        texts = [json.loads(r["payload"])["text"] for r in store.alert_rows()]
    assert (
        "ZuesScan: root: scope change proposed — scope lab2: it waits for another admin's "
        "approval; see the audit trail"
    ) in texts
    assert (
        "ZuesScan: carol: scope change rejected — scope lab2: nothing changed; see the audit trail"
    ) in texts


def test_scope_approval_is_set_by_the_server_not_the_dashboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zues_scan.server.config import ConfigError, from_environment, load_config

    (tmp_path / "s.toml").write_text(
        f'[service]\ndb = "{tmp_path.as_posix()}/x.db"\nscope_approval = "yes"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="scope_approval must be true or false"):
        load_config(tmp_path / "s.toml")
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "x.db"))
    monkeypatch.setenv("ZUES_SCOPE_APPROVAL", "on")
    assert from_environment().scope_approval is True
    monkeypatch.setenv("ZUES_SCOPE_APPROVAL", "maybe")
    with pytest.raises(ConfigError, match="ZUES_SCOPE_APPROVAL must be on or off"):
        from_environment()


def test_settings_show_installed_plugins_the_service_does_not_load(
    svc: App, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_plugins import Entry, spec

    from zues_scan.plugins import registry

    monkeypatch.setattr(registry, "_entry_points", lambda: [Entry("probe", spec(), "zues-probe")])
    root = svc.client(ROOT)
    settings = root.get("/api/v1/admin/config").json()
    assert "probe" not in {p["name"] for p in settings["plugins"]}
    [row] = settings["plugins_left_out"]
    assert row["name"] == "probe" and "but not allowed in" in row["reason"]

    assert root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).status_code == 200
    target = {"target": "scanme.lab", "scope": "lab2", "checks": ["probe"]}
    saved = root.put("/api/v1/admin/targets/web", json=target)
    assert saved.status_code == 422 and "plugin probe is not loaded" in saved.text


# --- a scope's history (G30) ---------------------------------------------------------------------

WIDER = SCOPE + "10.0.1.0/24\n"


def scope_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_a_scope_history_lists_its_versions_and_gives_their_text(svc: App) -> None:
    root = svc.client(ROOT)
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE}).status_code == 200
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": WIDER}).status_code == 200

    history = root.get("/api/v1/admin/scopes/lab2/history").json()
    assert history["current_sha256"] == scope_sha(WIDER)
    newest, first = history["events"]
    assert (newest["action"], newest["by"], newest["version"], newest["kept"]) == (
        "scope saved",
        "root",
        True,
        True,
    )
    assert (newest["sha256"], newest["previous_sha256"]) == (scope_sha(WIDER), scope_sha(SCOPE))
    assert first["sha256"] == scope_sha(SCOPE) and first["previous_sha256"] is None

    old = root.get(f"/api/v1/admin/scopes/lab2/versions/{scope_sha(SCOPE).upper()}").json()
    assert old == {"name": "lab2", "sha256": scope_sha(SCOPE), "text": SCOPE}

    # Restoring is saving the old text again: an ordinary, audited change.
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": old["text"]}).status_code == 200
    restored = root.get("/api/v1/admin/scopes/lab2/history").json()
    assert restored["current_sha256"] == scope_sha(SCOPE) and len(restored["events"]) == 3


def test_a_version_is_only_one_the_scope_had(svc: App) -> None:
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    root.put("/api/v1/admin/scopes/other", json={"text": WIDER})
    other = scope_sha(WIDER)
    assert root.get(f"/api/v1/admin/scopes/lab2/versions/{other}").status_code == 404
    assert root.get(f"/api/v1/admin/scopes/lab2/versions/{other[:12]}").status_code == 422
    assert root.get("/api/v1/admin/scopes/nope/history").status_code == 404
    for token in (ALICE, BOB):  # operator, viewer: scopes are admins' business
        client = svc.client(token)
        assert client.get("/api/v1/admin/scopes/lab2/history").status_code == 403
        assert (
            client.get(f"/api/v1/admin/scopes/lab2/versions/{scope_sha(SCOPE)}").status_code == 403
        )


def test_a_deleted_scope_keeps_its_history(svc: App) -> None:
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    assert root.delete("/api/v1/admin/scopes/lab2").status_code == 204
    history = root.get("/api/v1/admin/scopes/lab2/history").json()
    assert history["current_sha256"] is None
    assert [e["action"] for e in history["events"]] == ["scope deleted", "scope saved"]
    text = root.get(f"/api/v1/admin/scopes/lab2/versions/{scope_sha(SCOPE)}").json()["text"]
    assert text == SCOPE


def test_proposals_and_decisions_are_in_the_history(svc: App) -> None:
    with_approval(svc)
    root = svc.client(ROOT)
    pid = root.put(
        "/api/v1/admin/scopes/lab2", json={"text": SCOPE, "reason": "PT-9 signed"}
    ).json()["proposal"]
    rotated_admin(svc, "carol").post(f"/api/v1/admin/proposals/{pid}/approve", json={})
    events = root.get("/api/v1/admin/scopes/lab2/history").json()["events"]
    assert [(e["action"], e["version"]) for e in events] == [
        ("scope saved", True),
        ("scope change proposed", False),
    ]
    assert events[0]["by"] == "carol" and events[0]["proposed_by"] == "root"
    assert events[1]["note"] == "PT-9 signed"  # (its text is kept: it was approved)
