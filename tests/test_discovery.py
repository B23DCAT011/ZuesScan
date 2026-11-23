"""Tests for name discovery (subfinder) and wildcard scope entries."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import FakePlugin, fake_resolver

from zues_scan import cli
from zues_scan.orchestrator import NoPluginAvailableError, Orchestrator
from zues_scan.plugins.base import DiscoveryPlugin, DiscoveryResult, ScanError
from zues_scan.plugins.subfinder import SubfinderPlugin
from zues_scan.schema import Asset, RawOutput, Service
from zues_scan.scope import Scope, ScopeError
from zues_scan.storage import Storage

DNS = fake_resolver(
    {
        "example.com": ["10.0.0.5"],
        "api.example.com": ["10.0.0.5"],
        "www.example.com": ["10.0.0.7"],
        "cdn.example.com": ["203.0.113.9"],  # someone else's machine
    }
)
JSONL = "\n".join(
    [
        '{"host":"www.example.com","input":"example.com","source":"crtsh"}',
        '{"host":"API.example.com","input":"example.com","source":"dnsdumpster"}',
        '{"host":"api.example.com","input":"example.com","source":"crtsh"}',
        '{"host":"cdn.example.com","input":"example.com","source":"crtsh"}',
        '{"host":"ghost.example.com","input":"example.com","source":"crtsh"}',
        '{"host":"*.example.com","input":"example.com","source":"crtsh"}',
        '{"host":"evil.com","input":"example.com","source":"crtsh"}',
        "not json",
    ]
)


def _scope(*extra: str) -> Scope:
    return Scope.from_entries(["example.com", "*.example.com", "10.0.0.0/24", *extra])


# --- wildcard scope ---------------------------------------------------------------------------


def test_wildcard_authorises_names_under_it_only() -> None:
    scope = Scope.from_entries(["*.example.com", "!*.dev.example.com", "!admin.example.com"])
    assert scope.name_allowed("api.example.com")
    assert scope.name_allowed("a.b.example.com")
    assert not scope.name_allowed("example.com")  # the apex needs its own entry
    assert not scope.name_allowed("notexample.com")
    assert not scope.name_allowed("x.dev.example.com")
    assert not scope.name_allowed("admin.example.com")
    assert scope.allows_discovery("example.com")
    assert scope.allows_discovery("dev.example.com")
    assert not scope.allows_discovery("example.org")


def test_discovered_names_are_planned_one_by_one() -> None:
    plan, skipped = _scope().plan_discovered(
        "example.com",
        ["www.example.com", "api.example.com", "cdn.example.com", "x.example.com"],
        DNS,
    )
    assert plan.addresses == ("10.0.0.5", "10.0.0.7")
    assert plan.names_for("10.0.0.5") == ["api.example.com", "example.com"]
    assert plan.names_for("10.0.0.7") == ["www.example.com"]
    reasons = dict(skipped)
    assert "resolves to 203.0.113.9" in reasons["cdn.example.com"]  # name ok, machine not
    assert "cannot resolve" in reasons["x.example.com"]


def test_nothing_in_scope_is_a_refusal() -> None:
    with pytest.raises(ScopeError, match="none of the 2 name"):
        Scope.from_entries(["*.example.com"]).plan_discovered(
            "example.com", ["cdn.example.com"], DNS
        )


# --- the subfinder plugin -----------------------------------------------------------------------


def test_output_is_read_cleaned_and_kept_to_the_domain() -> None:
    names, skipped = SubfinderPlugin.parse_jsonl(JSONL, "example.com")
    assert names == ["api.example.com", "cdn.example.com", "ghost.example.com", "www.example.com"]
    assert skipped == 3  # the wildcard, the other domain, the broken line


def _fake_run(monkeypatch: pytest.MonkeyPatch, outcome: object) -> list[list[str]]:
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> object:
        commands.append(command)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/subfinder")
    monkeypatch.setattr(subprocess, "run", run)
    return commands


def test_discover_runs_subfinder_and_keeps_its_output(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(["subfinder"], 0, stdout=JSONL, stderr="")
    _fake_run(monkeypatch, done)
    result = SubfinderPlugin().discover("example.com")
    assert result.names[0] == "api.example.com"
    (raw,) = result.raw
    assert (raw.plugin, raw.format, raw.content) == ("subfinder", "subfinder-jsonl", JSONL)
    assert raw.command[:3] == ("subfinder", "-d", "example.com")
    assert result.notes == ["ignored 3 line(s) of subfinder output it could not read"]


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (subprocess.CalledProcessError(1, "subfinder", stderr="bad flag"), "exited with code 1"),
        (subprocess.TimeoutExpired("subfinder", 5), "timed out"),
        (PermissionError("denied"), "could not start"),
    ],
)
def test_subfinder_failures_are_scan_errors(
    monkeypatch: pytest.MonkeyPatch, outcome: Exception, message: str
) -> None:
    _fake_run(monkeypatch, outcome)
    with pytest.raises(ScanError, match=message):
        SubfinderPlugin(timeout=5).discover("example.com")


def test_missing_subfinder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert not SubfinderPlugin().is_available()
    with pytest.raises(ScanError, match="not installed"):
        SubfinderPlugin().discover("example.com")


def test_version(monkeypatch: pytest.MonkeyPatch) -> None:
    banner = subprocess.CompletedProcess([], 0, stdout="", stderr="[INF] Current Version: v2.6.6\n")
    _fake_run(monkeypatch, banner)
    assert SubfinderPlugin().version() == "2.6.6"
    assert isinstance(SubfinderPlugin(), DiscoveryPlugin)


# --- the pipeline --------------------------------------------------------------------------------


class FakeDiscovery:
    name = "finder"

    def __init__(self, names: list[str], available: bool = True) -> None:
        self.names = names
        self.available = available

    def is_available(self) -> bool:
        return self.available

    def version(self) -> str | None:
        return "0.9"

    def discover(self, domain: str) -> DiscoveryResult:
        raw = RawOutput("finder", "text", ("finder", domain), "\n".join(self.names))
        return DiscoveryResult(names=list(self.names), raw=[raw])


def _orch(
    discovery: list[DiscoveryPlugin], scanner: FakePlugin, scope: Scope | None = None
) -> Orchestrator:
    return Orchestrator([scanner], scope or _scope(), resolver=DNS, discovery=discovery)


def test_scan_covers_the_discovered_names_in_scope() -> None:
    scanner = FakePlugin(
        [
            Asset(host="10.0.0.5", ip="10.0.0.5", services=[Service(port=443)]),
            Asset(host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    run = _orch(
        [FakeDiscovery(["www.example.com", "api.example.com", "cdn.example.com"])], scanner
    ).run("example.com")
    (plan,) = scanner.seen
    assert plan.addresses == ("10.0.0.5", "10.0.0.7")  # never 203.0.113.9
    assert run.tool_versions == {"finder": "0.9", "fake": "1.0-fake"}
    assert [o.plugin for o in run.raw_outputs] == ["finder", "fake"]
    assert run.notes[0] == "discovery: 3 name(s) found under example.com; 3 in scope and scanned"
    assert run.notes[1].startswith(
        "not scanned: cdn.example.com: Target 'cdn.example.com' resolves"
    )


def test_discovery_needs_a_wildcard_and_a_tool() -> None:
    scanner = FakePlugin([])
    no_wildcard = Scope.from_entries(["example.com", "10.0.0.0/24"])
    with pytest.raises(ScopeError, match=r"needs '\*\.example\.com'"):
        _orch([FakeDiscovery([])], scanner, no_wildcard).run("example.com")
    with pytest.raises(ScopeError, match="top-level name"):
        _orch([FakeDiscovery([])], scanner).run("localhost")
    with pytest.raises(NoPluginAvailableError, match="finder"):
        _orch([FakeDiscovery([], available=False)], scanner).run("example.com")
    assert scanner.seen == []


def test_hosts_are_named_after_the_names_pointing_at_them() -> None:
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5")])  # tools see addresses
    run = _orch([FakeDiscovery(["api.example.com"])], scanner).run("example.com")
    (asset,) = run.assets
    assert (asset.host, asset.names) == ("api.example.com", ["api.example.com", "example.com"])


def test_names_are_stored(tmp_path: Path) -> None:
    from zues_scan.orchestrator import ScanRun

    run = ScanRun("example.com", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00")
    run.assets = [
        Asset(host="api.example.com", ip="10.0.0.5", names=["api.example.com", "x.example.com"])
    ]
    with Storage(tmp_path / "d.db") as store:
        loaded = store.load_run(store.save_run(run))
    assert loaded is not None and loaded.assets[0].names == ["api.example.com", "x.example.com"]


def test_cli_discover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", DNS)
    monkeypatch.setattr(
        "zues_scan.plugins.registry.SubfinderPlugin", lambda **_: FakeDiscovery(["api.example.com"])
    )
    asset = Asset(host="10.0.0.5", ip="10.0.0.5", services=[Service(port=443, name="https")])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: FakePlugin([asset]))
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n*.example.com\n10.0.0.0/24\n", encoding="utf-8")
    argv = ["scan", "example.com", "--discover", "--scope", str(scope), "--db", str(tmp_path / "d")]
    assert cli.main(argv) == 0
    captured = capsys.readouterr()
    assert (
        "note: discovery: 1 name(s) found under example.com; 2 in scope and scanned" in captured.err
    )
    assert "api.example.com (10.0.0.5)" in captured.out
    assert "names: api.example.com, example.com" in captured.out
