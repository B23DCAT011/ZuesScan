"""The scanner role (G26): what an AI agent or a script needs - read, and request scans of
its targets - and nothing more: no decision about a finding, no setting. viewer < scanner
< operator < admin."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("fakeredis")

from test_server_web import TOKENS, App, config_text, scan_once, sha  # noqa: E402

from zues_scan import cli  # noqa: E402
from zues_scan.server import managed  # noqa: E402
from zues_scan.server.config import ROLES, ConfigError, load_config  # noqa: E402

AGENT = "agent-scanner-token-0123456789abcdefghijklm"


@pytest.fixture
def svc(tmp_path: Path) -> App:
    app = App(tmp_path)
    agent = f'[[tokens]]\nname = "agent"\nsha256 = "{sha(AGENT)}"\nrole = "scanner"\n'
    app.rewrite(config_text(tmp_path.as_posix(), TOKENS + agent + "scans_per_hour = 2\n\n"))
    return app


def test_the_roles_in_order() -> None:
    assert ROLES == ("viewer", "scanner", "operator", "admin")
    assert managed.can("scanner", "scanner") and managed.can("operator", "scanner")
    assert not managed.can("viewer", "scanner") and not managed.can("scanner", "operator")


def test_a_scanner_requests_scans_and_decides_nothing(svc: App) -> None:
    agent = svc.client(AGENT)
    assert agent.get("/api/v1/me").json()["role"] == "scanner"
    response = agent.post("/api/v1/scans", json={"target": "lab"})
    assert response.status_code == 202, response.text
    assert response.json()["job"]["operator"] == "agent"
    svc.work()

    decision = agent.post("/api/v1/findings/1/decision", json={"action": "reopen"})
    assert decision.status_code == 403 and "operator" in decision.json()["detail"]
    assert agent.get("/api/v1/admin/config").status_code == 403
    assert agent.get("/api/v1/findings").status_code == 200  # it reads


def test_its_quota_and_target_list_apply(svc: App) -> None:
    agent = svc.client(AGENT)
    assert agent.post("/api/v1/scans", json={"target": "lab"}).status_code == 202
    svc.work()
    assert agent.post("/api/v1/scans", json={"target": "dmz"}).status_code == 202
    svc.work()
    assert agent.post("/api/v1/scans", json={"target": "lab"}).status_code == 429


def test_a_viewer_is_told_what_it_needs(svc: App) -> None:
    from test_server_web import BOB

    response = svc.client(BOB).post("/api/v1/scans", json={"target": "lab"})
    assert response.status_code == 403
    assert response.json()["detail"] == "this needs a scanner, operator or admin token"


def test_the_others_still_can(svc: App) -> None:
    assert scan_once(svc)["operator"] == "alice"  # an operator scans too


def test_made_from_the_dashboard_and_the_cli(svc: App, capsys: pytest.CaptureFixture[str]) -> None:
    from zues_scan.storage import Storage

    with Storage(svc.db) as store:
        token = managed.create_token(store, load_config(svc.config), "ci-agent", "scanner", "root")
    assert {t.name: t.role for t in load_config(svc.config).tokens}["ci-agent"] == "scanner"
    assert svc.client(token).post("/api/v1/scans", json={"target": "lab"}).status_code == 202
    assert cli.main(["token", "--name", "bot", "--role", "scanner"]) == 0
    assert 'role = "scanner"' in capsys.readouterr().out


def test_a_viewer_still_has_no_quota(tmp_path: Path) -> None:
    from zues_scan.server.config import scan_quota

    assert scan_quota(3, "scanner", "x") == 3
    with pytest.raises(ConfigError, match="a viewer cannot request scans"):
        scan_quota(3, "viewer", "x")
