"""Deleted scopes and the history of targets and tokens (G30): from the audit trail, for
admins, never a token's value."""

from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("fakeredis")

from test_server_admin import ROOT, SCOPE, svc  # noqa: E402,F401 - the fixture
from test_server_web import ALICE, BOB, App  # noqa: E402

WIDER = "@engagement LAB-2\nscanme.lab\n10.0.0.0/16\n"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_a_deleted_scope_is_listed_until_it_is_made_again(svc: App) -> None:  # noqa: F811
    root = svc.client(ROOT)
    assert root.get("/api/v1/admin/config").json()["deleted_scopes"] == []
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    root.put("/api/v1/admin/scopes/lab2", json={"text": WIDER})
    root.put("/api/v1/admin/scopes/keep", json={"text": SCOPE})
    assert root.delete("/api/v1/admin/scopes/lab2").status_code == 204

    (gone,) = root.get("/api/v1/admin/config").json()["deleted_scopes"]
    assert (gone["name"], gone["deleted_by"], gone["last_sha256"]) == ("lab2", "root", sha(WIDER))
    # Restoring is making it again from that version: an ordinary, audited save.
    text = root.get(f"/api/v1/admin/scopes/lab2/versions/{gone['last_sha256']}").json()["text"]
    assert root.put("/api/v1/admin/scopes/lab2", json={"text": text}).status_code == 200
    assert root.get("/api/v1/admin/config").json()["deleted_scopes"] == []
    actions = [e["action"] for e in root.get("/api/v1/admin/scopes/lab2/history").json()["events"]]
    assert actions == ["scope saved", "scope deleted", "scope saved", "scope saved"]


def test_a_target_has_a_history_with_its_settings(svc: App) -> None:  # noqa: F811
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    target = {"target": "scanme.lab", "scope": "lab2", "profile": "quick", "every": "12h"}
    assert root.put("/api/v1/admin/targets/web", json=target).status_code == 200
    target["profile"] = "standard"
    assert root.put("/api/v1/admin/targets/web", json=target).status_code == 200
    assert root.delete("/api/v1/admin/targets/web").status_code == 204

    events = root.get("/api/v1/admin/targets/web/history").json()["events"]
    assert [(e["action"], e["by"]) for e in events] == [
        ("target deleted", "root"),
        ("target updated", "root"),
        ("target added", "root"),
    ]
    assert [e["settings"].get("profile") for e in events] == [None, "standard", "quick"]
    assert events[2]["settings"]["target"] == "scanme.lab"
    assert root.get("/api/v1/admin/targets/nope/history").status_code == 404


def test_a_token_history_never_holds_its_value(svc: App) -> None:  # noqa: F811
    root = svc.client(ROOT)
    made = root.post("/api/v1/admin/tokens", json={"name": "carol", "role": "scanner"}).json()
    root.put("/api/v1/admin/tokens/carol/quota", json={"scans_per_hour": 3})
    root.post("/api/v1/admin/tokens/carol/rotate", json={})
    root.delete("/api/v1/admin/tokens/carol")

    history = root.get("/api/v1/admin/tokens/carol/history")
    assert [e["action"] for e in history.json()["events"]] == [
        "token deleted",
        "token rotated",
        "token scan limit changed",
        "token created",
    ]
    assert history.json()["events"][3]["settings"]["role"] == "scanner"
    assert made["token"] not in history.text and sha(made["token"]) not in history.text


def test_only_admins_read_them(svc: App) -> None:  # noqa: F811
    root = svc.client(ROOT)
    root.put("/api/v1/admin/scopes/lab2", json={"text": SCOPE})
    root.put("/api/v1/admin/targets/web", json={"target": "scanme.lab", "scope": "lab2"})
    for token in (ALICE, BOB):
        client = svc.client(token)
        assert client.get("/api/v1/admin/targets/web/history").status_code == 403
        assert client.get("/api/v1/admin/tokens/root/history").status_code == 403
