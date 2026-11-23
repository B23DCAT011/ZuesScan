"""The web API and dashboard: who may do what, and that the data is the stored data.

FastAPI's TestClient drives the app in this process, with an in-memory Redis; scans
run through the real pipeline with a fake scanner. Skipped without the server extras.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
fakeredis = pytest.importorskip("fakeredis")

from conftest import FakePlugin, lab_asset, lab_resolver  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from rq import SimpleWorker  # noqa: E402

from zues_scan.schema import Service  # noqa: E402
from zues_scan.server.config import ConfigError  # noqa: E402
from zues_scan.server.web import COOKIE, DASHBOARD_CSP, create_app  # noqa: E402
from zues_scan.storage import Storage  # noqa: E402

ALICE = "alice-operator-token-0123456789abcdefghijkl"
BOB = "bob-viewer-token-0123456789abcdefghijklmnop"
VSFTPD = Service(port=21, name="ftp", product="vsftpd", version="2.3.4")  # CVE-2011-2523: P2


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def config_text(d: str, tokens: str) -> str:
    return (
        f'[service]\ndb = "{d}/zues.db"\nqueue = "web"\n\n{tokens}'
        f'[[targets]]\nname = "lab"\ntarget = "scanme.lab"\nscope = "{d}/scope.txt"\n'
        'profile = "quick"\nevery = "1h"\nengagement = "PT-7"\n\n'
        f'[[targets]]\nname = "dmz"\ntarget = "10.0.0.7"\nscope = "{d}/scope.txt"\n'
        f'credentials = "{d}/creds.toml"\n'
    )


TOKENS = (
    f'[[tokens]]\nname = "alice"\nsha256 = "{sha(ALICE)}"\nrole = "operator"\n\n'
    f'[[tokens]]\nname = "bob"\nsha256 = "{sha(BOB)}"\nrole = "viewer"\n\n'
)


@pytest.fixture(autouse=True)
def _lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_ipv4", lab_resolver)
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    fake = FakePlugin([lab_asset(VSFTPD)])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: fake)


class App:
    """The app, its Redis and its files."""

    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path
        (tmp_path / "scope.txt").write_text("scanme.lab\n10.0.0.0/24\n", encoding="utf-8")
        self.config = tmp_path / "service.toml"
        self.config.write_text(config_text(tmp_path.as_posix(), TOKENS), encoding="utf-8")
        self.redis = fakeredis.FakeRedis()
        self.app = create_app(str(self.config), redis=self.redis)
        self.db = tmp_path / "zues.db"

    def client(self, token: str | None = None) -> TestClient:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return TestClient(self.app, headers=headers)

    def work(self) -> None:
        from rq import Queue

        q = Queue("web", connection=self.redis)
        SimpleWorker([q], connection=self.redis).work(burst=True)

    def rewrite(self, text: str) -> None:
        self.config.write_text(text, encoding="utf-8")
        # Make sure the change is visible even on a coarse file clock.
        later = time.time() + 5
        os.utime(self.config, (later, later))


@pytest.fixture
def svc(tmp_path: Path) -> App:
    return App(tmp_path)


def scan_once(svc: App) -> dict[str, Any]:
    response = svc.client(ALICE).post("/api/v1/scans", json={"target": "lab"})
    assert response.status_code == 202, response.text
    svc.work()
    return dict(response.json()["job"])


# --- who may do what ---------------------------------------------------------------------------


def test_everything_under_the_api_needs_a_token(svc: App) -> None:
    anonymous = svc.client()
    for path in ("/api/v1/me", "/api/v1/runs", "/api/v1/findings", "/api/v1/targets"):
        response = anonymous.get(path)
        assert response.status_code == 401, path
        assert response.headers["www-authenticate"] == "Bearer"
    assert svc.client("not-a-token").get("/api/v1/me").status_code == 401
    assert anonymous.post("/api/v1/scans", json={"target": "lab"}).status_code == 401


def test_a_token_says_who_and_which_role(svc: App) -> None:
    assert svc.client(ALICE).get("/api/v1/me").json()["name"] == "alice"
    bob = svc.client(BOB).get("/api/v1/me").json()
    assert (bob["name"], bob["role"]) == ("bob", "viewer")


def test_a_viewer_cannot_scan_or_decide(svc: App) -> None:
    viewer = svc.client(BOB)
    response = viewer.post("/api/v1/scans", json={"target": "lab"})
    assert response.status_code == 403 and "operator" in response.json()["detail"]
    decision = viewer.post("/api/v1/findings/1/decision", json={"action": "reopen"})
    assert decision.status_code == 403
    assert svc.redis.keys("rq:job:*") == []


def test_a_scan_request_can_only_name_a_configured_target(svc: App) -> None:
    operator = svc.client(ALICE)
    unknown = operator.post("/api/v1/scans", json={"target": "10.0.0.9"})
    assert unknown.status_code == 404
    # It cannot bring its own address, scope or options either.
    smuggled = operator.post("/api/v1/scans", json={"target": "lab", "scope": "0.0.0.0/0"})
    assert smuggled.status_code == 422
    assert svc.redis.keys("rq:job:*") == []


def test_a_revoked_token_stops_working_at_the_next_request(svc: App) -> None:
    bob = svc.client(BOB)
    assert bob.get("/api/v1/me").status_code == 200

    only_alice = f'[[tokens]]\nname = "alice"\nsha256 = "{sha(ALICE)}"\nrole = "operator"\n\n'
    svc.rewrite(config_text(svc.dir.as_posix(), only_alice))

    assert bob.get("/api/v1/me").status_code == 401
    assert svc.client(ALICE).get("/api/v1/me").status_code == 200


def test_a_broken_config_edit_fails_closed(svc: App) -> None:
    svc.rewrite("[service\n")  # a typo: the old tokens must not keep working

    response = svc.client(ALICE).get("/api/v1/me")
    assert response.status_code == 503
    assert "service.toml" not in response.text  # no detail to anonymous callers
    assert svc.client().get("/healthz").json()["checks"]["config"] is False

    svc.rewrite(config_text(svc.dir.as_posix(), TOKENS))
    assert svc.client(ALICE).get("/api/v1/me").status_code == 200


def test_the_app_does_not_start_on_an_invalid_config(tmp_path: Path) -> None:
    (tmp_path / "service.toml").write_text("[service]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="needs db"):
        create_app(str(tmp_path / "service.toml"))


# --- the browser session -----------------------------------------------------------------------


def test_the_browser_session_is_an_httponly_strict_cookie(svc: App) -> None:
    browser = svc.client()
    assert browser.post("/api/v1/session", json={"token": "wrong"}).status_code == 401

    response = browser.post("/api/v1/session", json={"token": BOB})

    assert response.status_code == 200 and response.json() == {"name": "bob", "role": "viewer"}
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Secure" not in cookie  # plain http in this test; https sets it
    assert browser.get("/api/v1/me").json()["name"] == "bob"

    assert browser.delete("/api/v1/session").status_code == 204
    assert browser.get("/api/v1/me").status_code == 401


def test_the_cookie_over_https_is_secure(svc: App) -> None:
    browser = TestClient(svc.app, base_url="https://zues.example")
    cookie = browser.post("/api/v1/session", json={"token": BOB}).headers["set-cookie"]
    assert "Secure" in cookie


def test_a_change_made_with_the_cookie_needs_the_csrf_header(svc: App) -> None:
    browser = svc.client()
    browser.post("/api/v1/session", json={"token": ALICE})

    forged = browser.post("/api/v1/scans", json={"target": "lab"})  # what another site could send
    assert forged.status_code == 403 and "X-ZuesScan" in forged.json()["detail"]
    assert svc.redis.keys("rq:job:*") == []

    ours = browser.post("/api/v1/scans", json={"target": "lab"}, headers={"X-ZuesScan": "1"})
    assert ours.status_code == 202


# --- scans, jobs, runs -------------------------------------------------------------------------


def test_an_operator_queues_a_scan_that_runs_as_them(svc: App) -> None:
    job = scan_once(svc)

    assert (job["target"], job["operator"], job["status"]) == ("lab", "alice", "queued")
    finished = svc.client(BOB).get(f"/api/v1/jobs/{job['id']}").json()
    assert finished["status"] == "finished"
    assert finished["result"]["run_id"] == 1 and finished["result"]["code"] == 0
    with Storage(svc.db) as store:
        run = store.load_run(1)
    assert run is not None and run.operator == "alice" and run.engagement == "PT-7"

    listed = svc.client(BOB).get("/api/v1/jobs").json()
    assert [j["id"] for j in listed] == [job["id"]]


def test_unknown_jobs_are_404(svc: App) -> None:
    viewer = svc.client(BOB)
    assert viewer.get("/api/v1/jobs/no-such-job").status_code == 404
    assert viewer.get("/api/v1/jobs/..%2F..%2Fetc").status_code == 404


def test_targets_list_the_config_without_secrets(svc: App) -> None:
    lab, dmz = svc.client(BOB).get("/api/v1/targets").json()
    assert (lab["name"], lab["every_seconds"], lab["authenticated"]) == ("lab", 3600, False)
    assert (dmz["name"], dmz["every_seconds"], dmz["authenticated"]) == ("dmz", None, True)
    assert "creds.toml" not in str(dmz)  # where the SSH keys live is not shown
    assert lab["last_started_at"] is None

    scan_once(svc)
    lab, _ = svc.client(BOB).get("/api/v1/targets").json()
    assert lab["last_started_at"] is not None


def test_runs_are_read_from_the_database(svc: App) -> None:
    viewer = svc.client(BOB)
    assert viewer.get("/api/v1/runs").json() == []  # no database yet...
    assert not svc.db.exists()  # ...and reading did not create one
    assert viewer.get("/api/v1/runs/1").status_code == 404

    scan_once(svc)

    [run] = viewer.get("/api/v1/runs").json()
    assert (run["id"], run["status"], run["findings"]) == (1, "completed", 1)
    model = viewer.get("/api/v1/runs/1").json()
    assert model["format"] == "zues-report" and model["run"]["operator"] == "alice"
    assert model["hosts"][0]["findings"][0]["cve"] == "CVE-2011-2523"


def test_the_report_page_keeps_its_own_strict_csp(svc: App) -> None:
    scan_once(svc)

    response = svc.client(BOB).get("/api/v1/runs/1/report.html")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    assert csp.startswith("default-src 'none'; script-src 'sha256-")
    assert csp.endswith("frame-ancestors 'none'")
    assert "CVE-2011-2523" in response.text


def test_sarif_is_a_download(svc: App) -> None:
    scan_once(svc)
    response = svc.client(BOB).get("/api/v1/runs/1/sarif")
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert "attachment" in response.headers["content-disposition"]
    assert response.json()["version"] == "2.1.0"


# --- findings and decisions --------------------------------------------------------------------


def test_findings_are_ranked_and_filtered(svc: App) -> None:
    scan_once(svc)
    viewer = svc.client(BOB)

    [f] = viewer.get("/api/v1/findings").json()
    assert (f["cve"], f["status"], f["priority"]) == ("CVE-2011-2523", "new", "P2")
    assert viewer.get("/api/v1/findings", params={"status": "fixed"}).json() == []
    assert len(viewer.get("/api/v1/findings", params={"all": "true"}).json()) == 1
    assert viewer.get("/api/v1/findings", params={"status": "bogus"}).status_code == 422


def test_an_operator_decision_is_recorded_under_their_name(svc: App) -> None:
    scan_once(svc)
    operator = svc.client(ALICE)

    response = operator.post(
        "/api/v1/findings/1/decision", json={"action": "claim_fixed", "note": "patched"}
    )

    assert response.status_code == 200 and response.json()["status"] == "fix_claimed"
    detail = svc.client(BOB).get("/api/v1/findings/1").json()
    last = detail["history"][-1]
    assert (last["event"], last["actor"], last["note"]) == ("fix_claimed", "alice", "patched")

    # The next scan still sees it: a fake fix, visible to everyone.
    scan_once(svc)
    assert svc.client(BOB).get("/api/v1/findings/1").json()["status"] == "fake_fix"

    audit = svc.client(BOB).get("/api/v1/audit").json()
    assert audit["chain"]["intact"] is True
    kinds = [e["kind"] for e in audit["events"]]
    assert kinds == ["scan", "finding", "scan"]  # newest first
    assert audit["events"][1]["operator"] == "alice"


def test_a_decision_that_is_not_allowed_is_refused(svc: App) -> None:
    scan_once(svc)
    operator = svc.client(ALICE)

    no_reason = operator.post("/api/v1/findings/1/decision", json={"action": "accept"})
    assert no_reason.status_code == 409 and "reason" in no_reason.json()["detail"]
    assert (
        operator.post("/api/v1/findings/9/decision", json={"action": "reopen"}).status_code == 404
    )
    bad = operator.post("/api/v1/findings/1/decision", json={"action": "delete"})
    assert bad.status_code == 422


def test_hosts_come_from_the_inventory(svc: App) -> None:
    scan_once(svc)
    [host] = svc.client(BOB).get("/api/v1/hosts").json()
    assert host["ip"] == "10.0.0.5"


# --- the page and the headers ------------------------------------------------------------------


def test_the_dashboard_is_served_with_a_strict_csp(svc: App) -> None:
    page = svc.client().get("/")
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == DASHBOARD_CSP
    assert '<script src="/static/app.js" defer></script>' in page.text
    script = svc.client().get("/static/app.js")
    assert script.headers["content-type"].startswith("text/javascript")
    assert "innerHTML" not in script.text.replace("never innerHTML", "")
    assert svc.client().get("/static/../web.py").status_code == 404
    assert svc.client().get("/static/index.html").status_code == 404


def test_every_response_has_the_security_headers(svc: App) -> None:
    for response in (svc.client().get("/api/v1/me"), svc.client(BOB).get("/api/v1/runs")):
        headers = response.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cache-control"] == "no-store"
        assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_health(svc: App) -> None:
    response = svc.client().get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {"config": True, "database": True, "queue": True},
    }


def test_health_reports_an_unreachable_queue(tmp_path: Path) -> None:
    (tmp_path / "service.toml").write_text(
        f'[service]\ndb = "{tmp_path.as_posix()}/x.db"\nredis_url = "redis://127.0.0.1:1/0"\n',
        encoding="utf-8",
    )
    client = TestClient(create_app(str(tmp_path / "service.toml")))
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["checks"] == {"config": True, "database": True, "queue": False}


def test_the_openapi_schema_is_published_but_no_cdn_docs(svc: App) -> None:
    client = svc.client()
    schema = client.get("/api/v1/openapi.json").json()
    assert "/api/v1/scans" in schema["paths"]
    assert client.get("/docs").status_code == 404
