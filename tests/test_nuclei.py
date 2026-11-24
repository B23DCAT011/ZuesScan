"""Tests for the nuclei check plugin — no binary required."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_resolver, lab_scope

from zues_scan import cli
from zues_scan.cve import LocalCveSource
from zues_scan.orchestrator import Orchestrator, RunStatus
from zues_scan.plugins.base import CheckPlugin, ScanError, ScanResult
from zues_scan.plugins.nuclei import NucleiPlugin, web_url
from zues_scan.profiles import BUILTIN, override
from zues_scan.schema import Asset, Confidence, ScanTarget, Service, Severity

SAMPLE = (Path(__file__).parent / "data" / "nuclei_sample.jsonl").read_text(encoding="utf-8")
APACHE = Service(port=8080, name="http", product="Apache httpd", version="2.4.49")
TLS = Service(port=443, name="https")
SSH = Service(port=22, name="ssh")
PLAN = ScanTarget("10.0.0.0/24", ("10.0.0.0/24",))


def _assets() -> list[Asset]:
    return [
        Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH, APACHE]),
        Asset(host="www.example.com", ip="10.0.0.7", services=[TLS], names=["www.example.com"]),
    ]


@pytest.mark.parametrize(
    ("ip", "service", "url"),
    [
        ("10.0.0.5", APACHE, "http://10.0.0.5:8080"),
        ("10.0.0.5", TLS, "https://10.0.0.5:443"),
        ("10.0.0.5", Service(port=8443, name="http"), "https://10.0.0.5:8443"),
        ("10.0.0.5", Service(port=8000, name="ssl/http"), "https://10.0.0.5:8000"),
        ("2001:db8::5", APACHE, "http://[2001:db8::5]:8080"),
        ("10.0.0.5", SSH, None),
        ("10.0.0.5", Service(port=80, protocol="udp", name="http"), None),
    ],
)
def test_web_urls_use_the_approved_address(ip: str, service: Service, url: str | None) -> None:
    assert web_url(ip, service) == url


def test_targets_are_grouped_by_virtual_host() -> None:
    assert NucleiPlugin.targets(_assets()) == {
        # SSH is checked too, by address (network and JavaScript templates).
        None: ["http://10.0.0.5:8080", "10.0.0.5:22"],
        "www.example.com": ["https://10.0.0.7:443"],
    }


def test_command_has_the_safe_defaults() -> None:
    plain = NucleiPlugin().command(None)
    assert {"-ni", "-duc", "-jsonl"} <= set(plain)
    assert plain[plain.index("-etags") + 1] == "dos,fuzz,intrusive,bruteforce"
    assert plain[plain.index("-rl") + 1] == "50"
    assert "-H" not in plain
    gentle = NucleiPlugin(BUILTIN["gentle"]).command("www.example.com")
    assert gentle[gentle.index("-rl") + 1] == "50"
    assert gentle[-4:] == ["-H", "Host: www.example.com", "-sni", "www.example.com"]
    fast = NucleiPlugin(override(BUILTIN["standard"], {"max_rate": 200}))
    assert fast.rate == 200


def test_output_becomes_findings() -> None:
    hits = NucleiPlugin.parse_jsonl(SAMPLE)
    assert [ip for ip, _ in hits] == ["10.0.0.5", "10.0.0.5", "10.0.0.7"]
    cve = hits[0][1]
    assert (cve.cve, cve.severity, cve.confidence) == (
        "CVE-2021-41773",
        Severity.CRITICAL,
        Confidence.CONFIRMED,  # the template sent the exploit request and saw the result
    )
    assert cve.rule_id == "nuclei:CVE-2021-41773"
    assert (cve.cvss_score, cve.cwe, cve.epss) == (9.8, ("CWE-22",), 0.94358)
    assert cve.service is not None and cve.service.port == 8080
    assert "matched at http://10.0.0.5:8080/cgi-bin/" in cve.evidence
    assert "extracted: root:x:0:0" in cve.evidence
    panel = hits[1][1]
    assert (panel.cve, panel.confidence, panel.rule_id) == (
        None,
        Confidence.FIRM,
        "nuclei:phpmyadmin-panel",
    )
    assert "(matcher title)" in panel.evidence


def test_a_virtual_host_is_part_of_the_check_identity() -> None:
    (_, f), *_ = NucleiPlugin.parse_jsonl(SAMPLE, "www.example.com")
    assert f.rule_id == "nuclei:CVE-2021-41773@www.example.com"
    assert "sent as virtual host www.example.com" in f.evidence


def _fake_nuclei(monkeypatch: pytest.MonkeyPatch, outcome: object) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> object:
        calls.append({"command": command, "input": kwargs.get("input")})
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(command, 0, stdout=str(outcome), stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nuclei")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_check_runs_once_per_virtual_host_and_ties_findings_to_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_nuclei(monkeypatch, SAMPLE)
    assets = _assets()
    result = NucleiPlugin().check(PLAN, assets)
    # Web services by URL; SSH in a run of its own, with the network templates only.
    assert [c["input"] for c in calls] == [
        "http://10.0.0.5:8080\n",
        "10.0.0.5:22\n",
        "https://10.0.0.7:443\n",
    ]
    assert "-pt" not in calls[0]["command"]
    assert calls[1]["command"][-2:] == ["-pt", "javascript,tcp,ssl"]
    assert "Host: www.example.com" in calls[2]["command"]
    assert len(result.raw) == 3 and result.raw[0].format == "nuclei-jsonl"
    assert result.raw[0].command[-2:] == ("<", "http://10.0.0.5:8080")
    assert not result.incomplete
    by_ip = {a.ip: a for a in result.assets}
    cve = by_ip["10.0.0.5"].findings[0]
    assert cve.service is APACHE  # the very service the port scan found


def test_nothing_to_check() -> None:
    plugin = NucleiPlugin()
    plugin.is_available = lambda: True  # type: ignore[method-assign]
    dns = Service(port=53, protocol="udp", name="domain")
    result = plugin.check(PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5", services=[dns])])
    assert result.assets == [] and result.notes == ["no service to check"]


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (subprocess.CalledProcessError(1, "nuclei", stderr="bad template"), "exited with code 1"),
        (OSError("gone"), "could not start"),
    ],
)
def test_nuclei_failures_are_scan_errors(
    monkeypatch: pytest.MonkeyPatch, outcome: Exception, message: str
) -> None:
    _fake_nuclei(monkeypatch, outcome)
    with pytest.raises(ScanError, match=message):
        NucleiPlugin(timeout=5).check(PLAN, _assets())


def test_version_and_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            [], 0, stdout="", stderr="[INF] Nuclei Engine Version: v3.3.7\n"
        ),
    )
    assert NucleiPlugin().version() == "3.3.7"
    assert isinstance(NucleiPlugin(), CheckPlugin)


# --- in the pipeline -----------------------------------------------------------------------------


class FakeCheck:
    name = "checker"

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.seen: list[list[Asset]] = []

    def is_available(self) -> bool:
        return self.available

    def version(self) -> str | None:
        return "3.0"

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        self.seen.append(assets)
        hits = NucleiPlugin.parse_jsonl(SAMPLE)
        found = [Asset(host=ip, ip=ip, findings=[f]) for ip, f in hits]
        found.append(Asset(host="8.8.8.8", ip="8.8.8.8", findings=[hits[0][1]]))  # not ours
        return ScanResult(assets=found, notes=["checked"])


def test_checks_run_after_the_scan_and_win_over_version_matches() -> None:
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE])])
    check = FakeCheck()
    orch = Orchestrator(
        [scanner],
        lab_scope("@activity active"),
        cve_source=LocalCveSource(),
        resolver=lab_resolver,
        checks=[check],
    )
    run = orch.run("10.0.0.5")
    assert [a.ip for a in check.seen[0]] == ["10.0.0.5"]  # it saw what the scan found
    (asset,) = run.assets
    cves = [f for f in asset.findings if f.cve == "CVE-2021-41773"]
    # The seed also matches Apache 2.4.49 to this CVE: one finding, the observed one.
    assert len(cves) == 1 and cves[0].confidence == Confidence.CONFIRMED
    assert {f.rule_id for f in asset.findings} == {
        "nuclei:CVE-2021-41773",
        "nuclei:phpmyadmin-panel",
    }
    assert run.tool_versions["checker"] == "3.0"
    assert "checker: checked" in run.notes
    assert all(a.ip != "8.8.8.8" for a in run.assets)  # a check cannot add hosts


def test_missing_check_tool_makes_the_run_partial() -> None:
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE])])
    orch = Orchestrator(
        [scanner], lab_scope("@activity active"), resolver=lab_resolver, checks=[FakeCheck(False)]
    )
    run = orch.run("10.0.0.5")
    assert (run.status, run.skipped_plugins) == (RunStatus.PARTIAL, ["checker"])


def test_cli_nuclei_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr(
        "zues_scan.plugins.registry.NmapPlugin",
        lambda **_: FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE])]),
    )
    made: list[object] = []

    def make(profile: object, **_: object) -> FakeCheck:
        made.append(profile)
        return FakeCheck()

    monkeypatch.setattr("zues_scan.plugins.registry.NucleiPlugin", make)
    scope = tmp_path / "scope.txt"
    scope.write_text("@activity active\n10.0.0.0/24\n", encoding="utf-8")
    argv = ["scan", "10.0.0.5", "--scope", str(scope), "--db", str(tmp_path / "d"), "--no-cve"]
    assert cli.main(argv) == 0
    assert made == []  # active checks only when asked for
    assert cli.main([*argv, "--nuclei"]) == 0
    assert len(made) == 1
    # EPSS 94 % (from the template): P2; the CVE was observed, so: confirmed.
    assert "P2 [CRITICAL, confirmed] Apache 2.4.49" in capsys.readouterr().out


def test_the_kept_exchange_has_the_targets_secrets_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    shadow = "root:$6$rOUNDsalt$Q8zjk1Z9jvzS0cSbG5u0Hk1bW2:19000:0:99999:7:::"
    hit = json.loads(SAMPLE.splitlines()[0])  # the CVE-2021-41773 match
    hit["extracted-results"] = [shadow]
    hit["response"] = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=7f3e9a\r\n\r\n" + shadow + "\n"
    _fake_nuclei(monkeypatch, json.dumps(hit) + "\n")

    result = NucleiPlugin().check(PLAN, _assets())

    stored = result.raw[0].content
    assert "rOUNDsalt" not in stored and "7f3e9a" not in stored  # neither kept nor hashed
    assert "Set-Cookie: sid=[redacted]" in stored
    finding = [f for a in result.assets for f in a.findings][0]  # (one per nuclei run)
    assert finding.cve == "CVE-2021-41773" and finding.confidence == Confidence.CONFIRMED
    assert "rOUNDsalt" not in finding.evidence and "CVE-2021-41773" in finding.evidence
