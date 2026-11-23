"""The naabu scanner plugin: nmap finds the live hosts, naabu their open ports, nmap the
services on those ports only."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import replace
from typing import Any

import pytest

from zues_scan.orchestrator import Orchestrator, RunStatus
from zues_scan.plugins import registry as plugin_registry
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.plugins.naabu import NaabuPlugin, parse_jsonl
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.profiles import BUILTIN, ScanProfile
from zues_scan.schema import Asset, RawOutput, ScanTarget, Service
from zues_scan.scope import Activity, Scope

TARGET = ScanTarget(requested="10.0.0.0/24", addresses=("10.0.0.0/24",), exclude=("10.0.0.9",))
UP = ("10.0.0.5", "10.0.0.12", "10.0.0.254")  # the router answers, nothing open on it


def line(ip: str, port: int, protocol: str = "tcp") -> str:
    return json.dumps({"ip": ip, "port": port, "protocol": protocol, "tls": False})


NAABU_OUT = "\n".join(
    [line("10.0.0.5", 80), line("10.0.0.5", 22), line("10.0.0.12", 6379), line("10.0.0.5", 80)]
)


class FakeNmap:
    """Stands in for NmapPlugin: `-sn` finds UP; `-sV` names 22 and 80 on 10.0.0.5."""

    made: list[FakeNmap] = []
    up: tuple[str, ...] = UP

    def __init__(self, profile: ScanProfile, ping_only: bool = False, available: bool = True):
        self.profile = profile
        self.ping_only = ping_only
        self.available = available
        self.targets: list[ScanTarget] = []
        FakeNmap.made.append(self)

    def is_available(self) -> bool:
        return self.available

    def version(self) -> str:
        return "7.95"

    def scan(self, target: ScanTarget) -> ScanResult:
        self.targets.append(target)
        if self.ping_only:
            if not self.up:
                raise ScanError("no host responded", plugin="nmap", no_response=True)
            raw = RawOutput("nmap", "nmap-xml", ("nmap", "-sn"), "<ping/>")
            return ScanResult(assets=[Asset(ip, ip) for ip in self.up], raw=[raw])
        web = Service(port=80, name="http", product="Apache httpd", version="2.4.49")
        ssh = Service(port=22, name="ssh", product="OpenSSH", version="8.9p1")
        raw = RawOutput("nmap", "nmap-xml", ("nmap", "-sV"), "<nmaprun/>")
        return ScanResult(assets=[Asset("10.0.0.5", "10.0.0.5", [ssh, web])], raw=[raw])


def made(ping_only: bool) -> list[FakeNmap]:
    return [n for n in FakeNmap.made if n.ping_only is ping_only and n.targets]


@pytest.fixture
def naabu(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """`subprocess.run` answering like naabu; returns the commands it got."""
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert kwargs["env"]["HOME"] == kwargs["env"]["USERPROFILE"]  # a throwaway home
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "", "[INF] Current Version: 2.7.0")
        return subprocess.CompletedProcess(command, 0, NAABU_OUT, "")

    FakeNmap.made, FakeNmap.up = [], UP
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    return commands


def test_parse_keeps_tcp_ports_once_per_host() -> None:
    junk = ["garbage", line("not-an-ip", 1), line("10.0.0.7", 0), line("10.0.0.7", 53, "udp")]
    text = NAABU_OUT + "\n" + "\n".join(junk)
    assert parse_jsonl(text) == ({"10.0.0.5": {22, 80}, "10.0.0.12": {6379}}, 4)


@pytest.mark.parametrize(
    ("ports", "top", "args", "note"),
    [
        ("22,80,8000-8100", None, ["-p", "22,80,8000-8100"], None),
        ("-", None, ["-tp", "full"], None),
        (None, None, ["-tp", "1000"], None),  # nmap's default: its top 1,000
        (None, 100, ["-tp", "100"], None),
        (None, 200, ["-tp", "1000"], "top 200 ports asked: naabu scanned its top 1000"),
        (None, 5000, ["-tp", "full"], "top 5000 ports asked: naabu scanned all ports"),
    ],
)
def test_the_profiles_ports(
    ports: str | None, top: int | None, args: list[str], note: str | None
) -> None:
    profile = ScanProfile("t", ports=ports, top_ports=top)
    assert NaabuPlugin(profile).ports() == (args, note)


def test_command_connect_scan_with_exclusions_and_rate() -> None:
    profile = ScanProfile("t", ports="22,80", max_rate=300, max_retries=1)
    command, _ = NaabuPlugin(profile).command(TARGET)
    assert command[command.index("-host") + 1] == "10.0.0.0/24"
    assert command[command.index("-eh") + 1] == "10.0.0.9"
    assert command[command.index("-s") + 1] == "c"  # no raw sockets needed
    assert command[command.index("-rate") + 1] == "300"
    assert command[command.index("-retries") + 1] == "1"


def test_nmap_pings_naabu_scans_the_live_hosts_nmap_names_their_services(
    naabu: list[list[str]],
) -> None:
    profile = replace(BUILTIN["full"], traceroute=True)
    result = NaabuPlugin(profile, nmap=FakeNmap).scan(TARGET)

    (pinger,) = made(ping_only=True)
    assert pinger.targets == [TARGET]
    (command,) = [c for c in naabu if "-host" in c]
    assert command[command.index("-host") + 1] == "10.0.0.5,10.0.0.12,10.0.0.254"  # live only

    (identifier,) = made(ping_only=False)
    assert identifier.profile.ports == "22,80,6379"
    assert identifier.profile.top_ports is None and identifier.profile.assume_up
    assert identifier.profile.traceroute  # the rest of the profile is kept
    (scanned,) = identifier.targets
    assert scanned.addresses == ("10.0.0.5", "10.0.0.12")  # those with open ports
    assert scanned.exclude == ("10.0.0.9",)

    web, redis, router = result.assets
    assert (router.ip, router.services) == ("10.0.0.254", [])  # up, nothing open: kept
    assert [(s.port, s.product) for s in web.services] == [(22, "OpenSSH"), (80, "Apache httpd")]
    assert [(s.port, s.name) for s in redis.services] == [(6379, None)]  # naabu's port kept
    assert [r.command[-1] if r.plugin == "nmap" else r.format for r in result.raw] == [
        "-sn",
        "naabu-jsonl",
        "-sV",
    ]
    assert "host discovery (nmap -sn): 3 host(s) up" in result.notes
    assert "3 open port(s) on 2 host(s)" in result.notes
    assert not result.incomplete


def test_assume_up_scans_every_address(naabu: list[list[str]]) -> None:
    profile = replace(BUILTIN["full"], assume_up=True)
    NaabuPlugin(profile, nmap=FakeNmap).scan(TARGET)
    assert made(ping_only=True) == []
    (command,) = [c for c in naabu if "-host" in c]
    assert command[command.index("-host") + 1] == "10.0.0.0/24"


def test_no_host_up_means_no_port_scan(naabu: list[list[str]]) -> None:
    FakeNmap.up = ()
    result = NaabuPlugin(BUILTIN["full"], nmap=FakeNmap).scan(TARGET)
    assert result.assets == [] and not [c for c in naabu if "-host" in c]
    assert any(n.startswith("host discovery (nmap -sn): no host responded") for n in result.notes)


def test_without_nmap_every_address_and_ports_only(naabu: list[list[str]]) -> None:
    def absent(profile: ScanProfile, **kw: Any) -> FakeNmap:
        return FakeNmap(profile, available=False, **kw)

    result = NaabuPlugin(BUILTIN["full"], nmap=absent).scan(TARGET)
    assert [len(a.services) for a in result.assets] == [2, 1]
    assert any(n.startswith("no host discovery (no nmap)") for n in result.notes)
    assert any("ports only (no nmap)" in n for n in result.notes)
    no_versions = replace(BUILTIN["full"], version_detection=False)
    result = NaabuPlugin(no_versions, nmap=FakeNmap).scan(TARGET)
    assert any("ports only (version_detection is off)" in n for n in result.notes)


def test_a_failed_service_detection_keeps_the_ports(naabu: list[list[str]]) -> None:
    class Broken(FakeNmap):
        def scan(self, target: ScanTarget) -> ScanResult:
            if self.ping_only:
                return super().scan(target)
            raise ScanError("nmap exited with code 1", plugin="nmap")

    result = NaabuPlugin(BUILTIN["full"], nmap=Broken).scan(TARGET)
    assert [len(a.services) for a in result.assets] == [2, 1, 0]
    assert result.incomplete
    assert any("service detection (nmap) failed" in n for n in result.notes)


def test_a_failed_host_discovery_fails_the_scan(naabu: list[list[str]]) -> None:
    class Broken(FakeNmap):
        def scan(self, target: ScanTarget) -> ScanResult:
            raise ScanError("could not start nmap: permission denied", plugin="nmap")

    with pytest.raises(ScanError, match=r"host discovery \(nmap -sn\) failed"):
        NaabuPlugin(BUILTIN["full"], nmap=Broken).scan(TARGET)


def test_nothing_open_is_an_empty_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    FakeNmap.made, FakeNmap.up = [], UP
    result = NaabuPlugin(BUILTIN["full"], nmap=FakeNmap).scan(TARGET)
    assert [(a.ip, a.services) for a in result.assets] == [(ip, []) for ip in UP]
    assert "0 open port(s) on 0 host(s)" in result.notes
    assert made(ping_only=False) == []  # nmap -sV had nothing to look at


def test_out_of_time_keeps_the_ports_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(command, 9, output=line("10.0.0.5", 80).encode())

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    profile = replace(BUILTIN["full"], version_detection=False)
    result = NaabuPlugin(profile, nmap=FakeNmap).scan(TARGET)
    assert [s.port for s in result.assets[0].services] == [80]
    assert result.incomplete


def test_failures_are_scan_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise subprocess.CalledProcessError(2, command, stderr="flag provided but not defined")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ScanError, match="naabu exited with code 2"):
        NaabuPlugin(replace(BUILTIN["full"], assume_up=True)).scan(TARGET)


def test_the_version_names_the_service_scanner_too(naabu: list[list[str]]) -> None:
    assert NaabuPlugin(nmap=FakeNmap).version() == "2.7.0 (services: nmap 7.95)"

    def absent(profile: ScanProfile, **kw: Any) -> FakeNmap:
        return FakeNmap(profile, available=False, **kw)

    assert NaabuPlugin(nmap=absent).version() == "2.7.0"


def test_nmap_ping_only_uses_the_profiles_pace_and_no_port_options() -> None:
    profile = ScanProfile("t", ports="-", timing=3, max_rate=200, max_retries=1, traceroute=True)
    command = NmapPlugin(profile, ping_only=True)._command(TARGET)
    assert command[1:7] == ["-sn", "-T3", "--max-rate", "200", "--max-retries", "1"]
    assert "-p" not in command and "-sV" not in command and "--traceroute" not in command
    assert command[-3:] == ["--exclude", "10.0.0.9", "10.0.0.0/24"]


def test_registered_as_a_scan_level_scanner() -> None:
    registry = plugin_registry.load(lambda: [])
    assert registry.get("naabu", "scanner").activity is Activity.SCAN
    ctx = plugin_registry.PluginContext(profile=BUILTIN["quick"])
    (built,) = registry.build(["naabu"], "scanner", ctx)
    assert built.profile is BUILTIN["quick"]
    assert built.nmap(BUILTIN["quick"], ping_only=True).ping_only


def test_an_incomplete_scanner_makes_the_run_partial() -> None:
    class Partial:
        name = "naabu"
        activity = Activity.SCAN

        def is_available(self) -> bool:
            return True

        def version(self) -> str:
            return "2.7.0"

        def scan(self, target: ScanTarget) -> ScanResult:
            asset = Asset("10.0.0.5", "10.0.0.5", [Service(port=80)])
            return ScanResult(assets=[asset], incomplete=True)

    scope = Scope.from_entries(["10.0.0.0/24"])
    run = Orchestrator([Partial()], scope).run("10.0.0.5")
    assert run.status is RunStatus.PARTIAL
