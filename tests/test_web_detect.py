"""A web service nmap misnames is found by httpx and tested as web by nuclei: a Spring
Boot app answering 404 JSON is "nagios-nsca" to nmap (measured on a Log4Shell app)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_resolver, lab_scope

from zues_scan.orchestrator import Orchestrator
from zues_scan.plugins.base import ScanResult
from zues_scan.plugins.httpx import HttpxPlugin
from zues_scan.plugins.nuclei import NucleiPlugin, network_target, web_url
from zues_scan.schema import Asset, ScanTarget, Service, WebPage

PLAN = ScanTarget("10.0.0.0/24", ("10.0.0.0/24",))
SPRING = Service(8080, name="nagios-nsca", product="Nagios NSCA")
SSH = Service(22, name="ssh", product="OpenSSH", version="9.6p1")


def test_nuclei_takes_what_httpx_saw_over_nmaps_name() -> None:
    plain = Service(8080, name="nagios-nsca", web=WebPage("http://10.0.0.9:8080", 404))
    tls = Service(8443, name="unknown", web=WebPage("https://10.0.0.9:8443", 200))
    assert web_url("10.0.0.9", plain) == "http://10.0.0.9:8080"
    assert web_url("fd00::9", tls) == "https://[fd00::9]:8443"
    assert network_target("10.0.0.9", plain) is None  # web now: not the network pass
    assert web_url("10.0.0.9", SPRING) is None  # nothing answered HTTP: as before
    assert network_target("10.0.0.9", SPRING) == "10.0.0.9:8080"
    rpc = Service(593, name="ncacn_http")  # RPC over HTTP, not a site
    assert web_url("10.0.0.9", rpc) is None


def test_httpx_says_where_a_web_service_was_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "", "[INF] Current Version: v1.12.0")
        inputs = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        assert inputs == ["10.0.0.9:8080"]  # not ssh
        line = {
            "input": "10.0.0.9:8080",
            "url": "http://10.0.0.9:8080",
            "status_code": 404,
            "failed": False,
            "tech": ["Spring Boot"],
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(line) + "\n", "")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    result = HttpxPlugin().check(PLAN, [Asset("10.0.0.9", "10.0.0.9", [SSH, SPRING])])
    (service,) = result.assets[0].services
    assert service.port == 8080 and service.web is not None and service.web.status == 404
    assert result.notes == [
        "1 of 1 other open port(s) answered HTTP: 10.0.0.9:8080 (nagios-nsca); "
        "tested as web services from here on",
    ]


class SawWeb:
    """httpx, faked: an HTTP answer on the port nmap called nagios-nsca."""

    name = "httpx"

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "1.12.0"

    def check(self, plan: ScanTarget, found: list[Asset]) -> ScanResult:
        page = WebPage("http://10.0.0.5:8080", 404, technologies=("Spring Boot",))
        return ScanResult(assets=[Asset("10.0.0.5", "10.0.0.5", [Service(8080, web=page)])])


class Inputs:
    """nuclei, faked: records what it would have been given."""

    name = "nuclei"

    def __init__(self) -> None:
        self.groups: list[dict[str | None, list[str]]] = []

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "3.11.1"

    def check(self, plan: ScanTarget, found: list[Asset]) -> ScanResult:
        self.groups.append(NucleiPlugin.targets(found))
        return ScanResult()


def test_in_the_pipeline_nuclei_tests_it_as_web() -> None:
    nuclei = Inputs()
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH, SPRING])])
    run = Orchestrator(
        [scanner],
        lab_scope("@activity active"),
        resolver=lab_resolver,
        checks=[SawWeb(), nuclei],
    ).run("10.0.0.5")
    assert nuclei.groups == [{None: ["http://10.0.0.5:8080", "10.0.0.5:22"]}]
    (spring,) = [s for s in run.assets[0].services if s.port == 8080]
    assert spring.name == "nagios-nsca" and spring.web is not None  # nmap's word is kept too
