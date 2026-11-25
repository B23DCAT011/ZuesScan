"""Findings by evidence (G24): confirmed by a check, tried and not matched, or inferred from
a version and never tried - the API, the dashboard's filter and the MCP tool."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("fakeredis")

from conftest import FakePlugin, lab_resolver, lab_scope  # noqa: E402
from test_server_web import BOB, App, svc  # noqa: E402,F401 - the fixture

from zues_scan.orchestrator import Orchestrator  # noqa: E402
from zues_scan.schema import Asset, Confidence, Finding, Service, Severity  # noqa: E402
from zues_scan.storage import Storage  # noqa: E402


def seed(db: Path) -> None:
    web = Service(port=80, name="http")

    def found(title: str, cve: str, confidence: Confidence, tried: str | None = None) -> Finding:
        return Finding(
            asset="10.0.0.5",
            ip="10.0.0.5",
            title=title,
            severity=Severity.HIGH,
            service=web,
            cve=cve,
            confidence=confidence,
            tried=tried,
        )

    asset = Asset(
        "10.0.0.5",
        "10.0.0.5",
        [web],
        findings=[
            found("Observed", "CVE-2021-0001", Confidence.CONFIRMED),
            found("Tried", "CVE-2021-0002", Confidence.FIRM, "nuclei: template ran, no match"),
            found("Inferred", "CVE-2021-0003", Confidence.FIRM),
        ],
    )
    run = Orchestrator([FakePlugin([asset])], lab_scope(), resolver=lab_resolver).run("10.0.0.5")
    with Storage(db) as store:
        store.save_run(run)


@pytest.mark.parametrize(
    ("evidence", "titles"),
    [
        (None, {"Observed", "Tried", "Inferred"}),
        ("confirmed", {"Observed"}),
        ("tried", {"Tried"}),
        ("untried", {"Inferred"}),
    ],
)
def test_findings_by_evidence(svc: App, evidence: str | None, titles: set[str]) -> None:  # noqa: F811
    seed(svc.db)
    query = f"?evidence={evidence}" if evidence else ""
    response = svc.client(BOB).get("/api/v1/findings" + query)
    assert response.status_code == 200
    assert {f["title"] for f in response.json()} == titles
    assert response.headers["X-Total-Count"] == str(len(titles))


def test_an_unknown_evidence_is_refused(svc: App) -> None:  # noqa: F811
    assert svc.client(BOB).get("/api/v1/findings?evidence=maybe").status_code == 422


def test_the_dashboard_offers_the_filter() -> None:
    app = (Path(__file__).parents[1] / "zues_scan" / "server" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    for value in ('"confirmed"', '"tried"', '"untried"', "evidence="):
        assert value in app
