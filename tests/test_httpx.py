"""The httpx check: what each web service is, kept on the service, versions to the CVE stage."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from zues_scan.cve import LocalCveSource
from zues_scan.cve.match import components
from zues_scan.orchestrator import Orchestrator
from zues_scan.plugins import registry as plugin_registry
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.plugins.httpx import HttpxPlugin, parse_jsonl
from zues_scan.profiles import BUILTIN
from zues_scan.schema import Asset, ScanTarget, Service, WebPage
from zues_scan.scope import Activity, Scope
from zues_scan.storage import Storage

PLAN = ScanTarget(requested="10.0.0.0/24", addresses=("10.0.0.0/24",))


def record(input_: str, **fields: Any) -> str:
    base = {"input": input_, "url": f"http://{input_}", "status_code": 200, "failed": False}
    return json.dumps(base | fields)


def assets() -> list[Asset]:
    return [
        Asset(
            "10.0.0.5",
            "10.0.0.5",
            [
                Service(22, name="ssh", product="OpenSSH", version="8.9p1"),
                Service(80, name="http", product="Apache httpd", version="2.4.49"),
                Service(8443, name="https-alt"),
                Service(53, protocol="udp", name="domain"),
            ],
        ),
        Asset("fd00::7", "fd00::7", [Service(8080)]),  # no name (naabu): a usual web port
        Asset("10.0.0.6", "10.0.0.6", [Service(6379)]),  # no name, not a web port
    ]


def test_only_web_services_by_address() -> None:
    assert HttpxPlugin.inputs(assets()) == ["10.0.0.5:80", "10.0.0.5:8443", "[fd00::7]:8080"]


def test_parse_cleans_what_the_machine_sent() -> None:
    text = "\n".join(
        [
            record(
                "10.0.0.5:80",
                title="Welcome‮\x1b[31m to   nginx!",
                webserver="nginx/1.20.0",
                tech=["Nginx:1.20.0", "PHP:7.4.3", "x" * 500],
            ),
            record("[fd00::7]:8080", url="https://[fd00::7]:8080", status_code=401),
            record("10.0.0.5:8443", failed=True),  # nothing answered: not a web page
            "garbage",
            json.dumps({"input": "no-port"}),
        ]
    )
    pages, skipped = parse_jsonl(text)
    assert skipped == 2
    nginx = pages[("10.0.0.5", 80)]
    assert nginx.title == "Welcome [31m to nginx!"  # control and direction characters gone
    assert nginx.technologies[:2] == ("Nginx:1.20.0", "PHP:7.4.3")
    assert len(nginx.technologies[2]) == 200
    assert pages[("fd00::7", 8080)] == WebPage(url="https://[fd00::7]:8080", status=401)


@pytest.fixture
def fake_httpx(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "", "[INF] Current Version: v1.12.0")
        inputs = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        calls.append({"command": command, "inputs": inputs, "env": kwargs["env"]})
        out = record("10.0.0.5:80", webserver="Apache/2.4.49 (Unix)", tech=["PHP:7.4.3"])
        return subprocess.CompletedProcess(command, 0, out, "")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_check_reports_pages_on_their_services(fake_httpx: list[dict[str, Any]]) -> None:
    plugin = HttpxPlugin(BUILTIN["full"])
    result = plugin.check(PLAN, assets())
    (call,) = fake_httpx
    command = call["command"]
    assert command[command.index("-rl") + 1] == str(BUILTIN["full"].check_rate or 50)
    assert "-fr=false" in command  # redirects are not followed
    assert call["env"]["HOME"] != str(Path.home())
    (asset,) = result.assets
    (service,) = asset.services
    assert (asset.ip, service.port, service.web and service.web.technologies) == (
        "10.0.0.5",
        80,
        ("PHP:7.4.3",),
    )
    assert "1 of 3 web service(s) answered" in result.notes
    assert result.raw[0].format == "httpx-jsonl"
    assert plugin.version() == "1.12.0"


def test_nothing_to_look_at_runs_nothing(fake_httpx: list[dict[str, Any]]) -> None:
    result = HttpxPlugin().check(PLAN, [Asset("10.0.0.6", "10.0.0.6", [Service(22, name="ssh")])])
    assert fake_httpx == [] and result.notes == ["no web service found to look at"]


def test_failures_are_scan_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise subprocess.CalledProcessError(1, command, stderr="bad flag")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ScanError, match="httpx exited with code 1"):
        HttpxPlugin().check(PLAN, assets())


def test_out_of_time_keeps_what_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(command, 3, output=record("10.0.0.5:80").encode())

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    result = HttpxPlugin().check(PLAN, assets())
    assert result.incomplete and len(result.assets) == 1


# --- technologies as software for the CVE stage ---------------------------------------------


def test_components_are_the_known_technologies_with_a_version() -> None:
    web = WebPage(
        "http://10.0.0.5:80",
        technologies=("Apache HTTP Server:2.4.49", "PHP:7.4.3", "UNIX", "jQuery", "Mystery:1.0"),
    )
    found = components(Service(80, name="http", web=web))
    assert found[0].banner == "web technology seen by httpx: Apache HTTP Server:2.4.49"
    assert [(s.product, s.version, s.cpe, s.port) for s in found] == [
        ("Apache HTTP Server", "2.4.49", "cpe:/a:apache:http_server:2.4.49", 80),
        ("PHP", "7.4.3", "cpe:/a:php:php:7.4.3", 80),
    ]
    assert components(Service(80)) == []


class Web:
    """A check that saw Apache 2.4.49 on port 80, and claims a port the scan never found."""

    name = "httpx"
    activity = Activity.SCAN

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "1.12.0"

    def check(self, plan: ScanTarget, found: list[Asset]) -> ScanResult:
        page = WebPage(
            "http://10.0.0.5:80", 200, "It works", technologies=("Apache HTTP Server:2.4.49",)
        )
        claimed = Service(9999, web=WebPage("http://10.0.0.5:9999"))
        return ScanResult(assets=[Asset("10.0.0.5", "10.0.0.5", [Service(80, web=page), claimed])])


class Ports:
    """A scanner that found port 80 open but could not name what runs there."""

    name = "naabu"
    activity = Activity.SCAN

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "2.7.0"

    def scan(self, target: ScanTarget) -> ScanResult:
        return ScanResult(assets=[Asset("10.0.0.5", "10.0.0.5", [Service(80)])])


def test_a_version_only_the_web_check_saw_reaches_the_cve_stage(tmp_path: Path) -> None:
    scope = Scope.from_entries(["10.0.0.0/24"])
    run = Orchestrator([Ports()], scope, checks=[Web()], cve_source=LocalCveSource()).run(
        "10.0.0.5"
    )
    (asset,) = run.assets
    (service,) = asset.services  # the port a check claimed on its own is not added
    assert service.web is not None and service.web.title == "It works"
    (finding,) = [f for f in asset.findings if f.cve == "CVE-2021-41773"]
    assert finding.evidence is not None
    assert "the web check (httpx) recognised 'Apache HTTP Server:2.4.49'" in finding.evidence

    with Storage(tmp_path / "zues.db") as store:
        run_id = store.save_run(run)
        loaded = store.load_run(run_id)
    assert loaded is not None
    assert loaded.assets[0].services[0].web == service.web  # kept in the database


def test_registered_as_a_scan_level_check() -> None:
    registry = plugin_registry.load(lambda: [])
    assert registry.get("httpx", "check").activity is Activity.SCAN
    ctx = plugin_registry.PluginContext(profile=BUILTIN["full"])
    (built,) = registry.build(["httpx"], "check", ctx)
    assert built.rate == (BUILTIN["full"].check_rate or 50)
