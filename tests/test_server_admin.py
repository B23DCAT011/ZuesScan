"""The admin API: scopes, targets and tokens edited in the dashboard, end to end."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("fakeredis")

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
