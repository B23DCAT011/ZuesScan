"""Per-target permissions (G23): a token limited to some targets sees and acts on them only.

Two customers' targets on one service: `acme-web` and `globex-lan`. The `acme` token is
limited to `acme-*`; everything else answers 404 to it, as if it did not exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("fakeredis")

from conftest import FakePlugin, lab_asset  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from test_server_web import VSFTPD, App, _lab, sha  # noqa: E402,F401

from zues_scan.orchestrator import RunStatus, ScanRun  # noqa: E402
from zues_scan.schema import Service  # noqa: E402
from zues_scan.server.config import ConfigError, load_config  # noqa: E402
from zues_scan.server.web import name_old_runs  # noqa: E402
from zues_scan.storage import Storage  # noqa: E402

ROOT = "root-admin-token-0123456789abcdefghijklmnopq"
OPS = "ops-operator-token-0123456789abcdefghijklmn"
ACME = "acme-operator-token-0123456789abcdefghijklm"
OPENSSH = Service(port=22, name="ssh", product="OpenSSH", version="7.4")


def service_text(d: str, acme_targets: str = '["acme-*"]') -> str:
    return (
        f'[service]\ndb = "{d}/zues.db"\nqueue = "web"\n\n'
        f'[[tokens]]\nname = "root"\nsha256 = "{sha(ROOT)}"\nrole = "admin"\n\n'
        f'[[tokens]]\nname = "ops"\nsha256 = "{sha(OPS)}"\nrole = "operator"\n\n'
        f'[[tokens]]\nname = "acme"\nsha256 = "{sha(ACME)}"\nrole = "operator"\n'
        f"targets = {acme_targets}\n\n"
        f'[[targets]]\nname = "acme-web"\ntarget = "scanme.lab"\nscope = "{d}/scope.txt"\n'
        'profile = "quick"\n\n'
        f'[[targets]]\nname = "globex-lan"\ntarget = "10.0.0.9"\nscope = "{d}/scope.txt"\n'
        'profile = "quick"\n'
    )


@pytest.fixture
def svc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> App:
    """Both customers scanned once: acme-web finds vsftpd, globex-lan OpenSSH."""
    app = App(tmp_path)
    app.rewrite(service_text(tmp_path.as_posix()))
    for name, asset in (
        ("acme-web", lab_asset(VSFTPD)),
        ("globex-lan", lab_asset(OPENSSH, host="10.0.0.9", ip="10.0.0.9")),
    ):
        fake = FakePlugin([asset])
        monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda fake=fake, **_: fake)
        queued = app.client(OPS).post("/api/v1/scans", json={"target": name})
        assert queued.status_code == 202, queued.text
        app.work()
    return app


def ids(response: Any) -> list[Any]:
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()]


def test_a_limited_token_sees_its_targets_only(svc: App) -> None:
    acme, ops = svc.client(ACME), svc.client(OPS)

    assert acme.get("/api/v1/me").json()["targets"] == ["acme-*"]
    assert [t["name"] for t in acme.get("/api/v1/targets").json()] == ["acme-web"]
    runs = acme.get("/api/v1/runs").json()
    assert [(r["id"], r["target_name"]) for r in runs] == [(1, "acme-web")]
    assert [r["target_name"] for r in ops.get("/api/v1/runs").json()] == ["globex-lan", "acme-web"]
    assert [j["target"] for j in acme.get("/api/v1/jobs").json()] == ["acme-web"]

    findings = acme.get("/api/v1/findings").json()
    assert [f["cve"] for f in findings] == ["CVE-2011-2523"]  # not globex's OpenSSH
    assert len(ops.get("/api/v1/findings").json()) == 2
    assert [h["host"] for h in acme.get("/api/v1/hosts").json()] == ["scanme.lab"]


def test_everything_else_is_404_as_if_it_did_not_exist(svc: App) -> None:
    acme, ops = svc.client(ACME), svc.client(OPS)
    globex_job = next(j for j in ops.get("/api/v1/jobs").json() if j["target"] == "globex-lan")
    globex_finding = next(f for f in ops.get("/api/v1/findings").json() if f["host"] == "10.0.0.9")

    for path in (
        "/api/v1/runs/2",
        "/api/v1/runs/2/report.html",
        "/api/v1/runs/2/sarif",
        "/api/v1/runs/2/diff",
        "/api/v1/runs/1/diff?against=2",
        f"/api/v1/jobs/{globex_job['id']}",
        f"/api/v1/findings/{globex_finding['id']}",
    ):
        assert acme.get(path).status_code == 404, path
    assert acme.get("/api/v1/runs/1").status_code == 200
    unknown = acme.post("/api/v1/scans", json={"target": "globex-lan"})
    assert unknown.status_code == 404
    assert unknown.json() == ops.post("/api/v1/scans", json={"target": "nope"}).json() | {
        "detail": "no target named 'globex-lan' in the service config"
    }
    decision = acme.post(
        f"/api/v1/findings/{globex_finding['id']}/decision", json={"action": "claim_fixed"}
    )
    assert decision.status_code == 404
    assert acme.post("/api/v1/scans", json={"target": "acme-web"}).status_code == 202


def test_the_audit_trail_is_for_unlimited_tokens(svc: App) -> None:
    refused = svc.client(ACME).get("/api/v1/audit")
    assert refused.status_code == 403 and "every target" in refused.json()["detail"]
    assert svc.client(OPS).get("/api/v1/audit").status_code == 200


def test_an_admin_limits_a_dashboard_token_at_once(svc: App) -> None:
    root = svc.client(ROOT)
    made = root.post(
        "/api/v1/admin/tokens", json={"name": "auditor", "role": "viewer", "targets": ["globex-*"]}
    ).json()
    browser = TestClient(svc.app)
    assert browser.post("/api/v1/session", json={"token": made["token"]}).status_code == 200
    assert [r["target_name"] for r in browser.get("/api/v1/runs").json()] == ["globex-lan"]

    changed = root.put("/api/v1/admin/tokens/auditor/targets", json={"targets": ["acme-web"]})
    assert changed.status_code == 200
    assert [r["target_name"] for r in browser.get("/api/v1/runs").json()] == ["acme-web"]
    root.put("/api/v1/admin/tokens/auditor/targets", json={"targets": None})
    assert len(browser.get("/api/v1/runs").json()) == 2

    listed = {t["name"]: t for t in root.get("/api/v1/admin/config").json()["tokens"]}
    assert listed["acme"]["targets"] == ["acme-*"] and listed["auditor"]["targets"] is None
    with Storage(svc.db) as store:
        actions = [e.detail for _, e, _ in store.audit_events() if e.target == "token:auditor"]
    assert [a["action"] for a in actions].count("token targets changed") == 2


def test_an_admin_is_never_limited(svc: App, tmp_path: Path) -> None:
    root = svc.client(ROOT)
    limited_admin = {"name": "x", "role": "admin", "targets": ["acme-*"]}
    refused = root.post("/api/v1/admin/tokens", json=limited_admin)
    assert (
        refused.status_code == 422 and "admin token sees every target" in refused.json()["detail"]
    )
    bad = root.post(
        "/api/v1/admin/tokens", json={"name": "y", "role": "viewer", "targets": ["A B"]}
    )
    assert bad.status_code == 422

    (tmp_path / "admin.toml").write_text(
        service_text(tmp_path.as_posix()).replace(
            'role = "admin"\n', 'role = "admin"\ntargets = ["a"]\n'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="admin token sees every target"):
        load_config(tmp_path / "admin.toml")


def test_runs_from_before_get_their_target_name(svc: App) -> None:
    old = ScanRun(
        target="scanme.lab",
        started_at="2026-11-01T02:00:00+00:00",
        finished_at="2026-11-01T02:01:00+00:00",
        status=RunStatus.COMPLETED,
        profile="quick",
    )
    other = ScanRun(
        target="192.0.2.50",
        started_at="2026-11-01T03:00:00+00:00",
        finished_at="2026-11-01T03:01:00+00:00",
        profile="quick",
    )
    with Storage(svc.db) as store:
        first, second = store.save_run(old), store.save_run(other)

    assert name_old_runs(load_config(svc.config)) == 1

    with Storage(svc.db) as store:
        assert store.run_target_name(first) == (True, "acme-web")
        assert store.run_target_name(second) == (True, None)  # no configured target: unnamed
    assert first in ids(svc.client(ACME).get("/api/v1/runs"))
    assert second not in ids(svc.client(ACME).get("/api/v1/runs"))
    assert second in ids(svc.client(OPS).get("/api/v1/runs"))


def test_signing_in_says_which_targets_the_page_may_show(svc: App) -> None:
    answer = TestClient(svc.app).post("/api/v1/session", json={"token": ACME}).json()
    assert answer == {"name": "acme", "role": "operator", "targets": ["acme-*"]}
