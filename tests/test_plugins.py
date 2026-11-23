"""Plugins: a registry anyone can add to with a package, what each one may do (@activity),
and the contract every plugin keeps."""

from __future__ import annotations

import http.server
import json
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver, lab_scope

from zues_scan import cli
from zues_scan.orchestrator import Orchestrator
from zues_scan.plugins import contract, registry
from zues_scan.plugins.base import DiscoveryResult, ScanResult
from zues_scan.plugins.registry import PluginContext, PluginError, PluginSpec
from zues_scan.schema import Asset, Finding, RawOutput, ScanTarget, Service
from zues_scan.scope import Activity, Scope, ScopeError
from zues_scan.server.config import ConfigError, load_config
from zues_scan.server.jobs import spec_for
from zues_scan.storage import Storage

EXAMPLE = Path(__file__).parent.parent / "examples" / "zues-exposed-git"
PLAN = ScanTarget("10.0.0.5", ("10.0.0.5",))


class Entry:
    """Stands in for an importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: Any, dist: str = "some-plugin") -> None:
        self.name, self._value = name, value
        self.value = f"{dist.replace('-', '_')}:PLUGIN"
        self.dist = type("Dist", (), {"name": dist})()

    def load(self) -> Any:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value


class Check:
    name = "probe"
    activity = Activity.SCAN

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "1.0"

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        return ScanResult()


class Silent:
    """A check that does not say how far it goes."""

    name = "probe"

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "1.0"

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        return ScanResult()


class NucleiLike(Check):
    name = "nuclei"
    activity = Activity.ACTIVE


def spec(
    name: str = "probe", kind: Any = "check", activity: Activity = Activity.SCAN
) -> PluginSpec:
    return PluginSpec(name, kind, activity, "a test plugin", lambda ctx: Check())


# --- the registry -------------------------------------------------------------------------------


def test_the_built_in_plugins() -> None:
    loaded = registry.load(lambda: [])
    assert {n: (s.kind, str(s.activity)) for n, s in loaded.plugins.items()} == {
        "nmap": ("scanner", "scan"),
        "naabu": ("scanner", "scan"),
        "nuclei": ("check", "active"),
        "httpx": ("check", "scan"),
        "ssh-packages": ("check", "scan"),
        "subfinder": ("discovery", "passive"),
        "dnsx": ("discovery", "scan"),
    }
    assert loaded.problems == []


def test_a_package_adds_a_plugin_and_a_broken_one_is_left_out() -> None:
    entries = [
        Entry("probe", spec(), dist="zues-probe"),
        Entry("lazy", lambda: spec("lazy"), dist="zues-lazy"),  # a function returning one
        Entry("broken", ImportError("No module named 'requests'")),
        Entry("wrong", object()),
        Entry("nmap", spec("nmap", "scanner")),  # may not replace a built-in
    ]
    loaded = registry.load(lambda: entries)

    assert loaded.plugins["probe"].source == "zues-probe"
    assert loaded.plugins["lazy"].source == "zues-lazy"
    assert loaded.plugins["nmap"].source == "built-in"
    assert len(loaded.problems) == 3
    assert "No module named 'requests'" in loaded.problems[0]
    assert "must name a PluginSpec" in loaded.problems[1]
    assert "already taken (built-in)" in loaded.problems[2]


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (("Bad Name", "check", Activity.SCAN), "lowercase letters"),
        (("probe", "exploit", Activity.SCAN), "kind must be one of"),
        (("probe", "check", "active"), "must be a zues_scan.scope.Activity"),
    ],
)
def test_a_spec_is_checked(args: tuple[Any, Any, Any], error: str) -> None:
    name, kind, activity = args
    with pytest.raises(PluginError, match=error):
        PluginSpec(name, kind, activity, "x", lambda ctx: None)


def test_build_by_name_and_kind() -> None:
    loaded = registry.load(lambda: [Entry("probe", spec())])
    built = loaded.build(["probe", "probe"], "check", PluginContext())
    assert len(built) == 1 and built[0].name == "probe"
    with pytest.raises(PluginError, match=r"unknown check plugin 'nope' \(available: nuclei, "):
        loaded.build(["nope"], "check", PluginContext())
    with pytest.raises(PluginError, match="nmap is a scanner plugin, not a check"):
        loaded.build(["nmap"], "check", PluginContext())


def test_a_plugin_cannot_claim_less_than_it_does() -> None:
    lying = PluginSpec("probe", "check", Activity.PASSIVE, "x", lambda ctx: Check())
    loaded = registry.load(lambda: [Entry("probe", lying)])
    with pytest.raises(PluginError, match="its activity differs"):
        loaded.build(["probe"], "check", PluginContext())


def test_ssh_packages_needs_its_settings() -> None:
    with pytest.raises(PluginError, match="needs --credentials and --cve-cache"):
        registry.load(lambda: []).build(["ssh-packages"], "check", PluginContext())


# --- @activity ----------------------------------------------------------------------------------


def test_a_scope_allows_scanning_unless_it_says_more() -> None:
    assert Scope.from_entries(["10.0.0.0/24"]).activity == Activity.SCAN
    assert Scope.from_entries(["@activity active", "10.0.0.0/24"]).activity == Activity.ACTIVE
    assert Scope.from_entries(["@activity passive"]).activity == Activity.PASSIVE
    with pytest.raises(ScopeError, match="unknown activity 'exploit'"):
        Scope.from_entries(["@activity exploit"])


def test_an_active_check_is_refused_before_anything_is_sent() -> None:
    scanner = FakePlugin([lab_asset()])
    orch = Orchestrator([scanner], lab_scope(), resolver=lab_resolver, checks=[NucleiLike()])
    with pytest.raises(ScopeError, match=r"nuclei \(active\) goes beyond .* '@activity active'"):
        orch.run("10.0.0.5")
    assert scanner.seen == []  # not even the port scan ran

    allowed = Orchestrator(
        [scanner], lab_scope("@activity active"), resolver=lab_resolver, checks=[NucleiLike()]
    )
    assert allowed.run("10.0.0.5").assets


def test_a_check_that_does_not_say_counts_as_active() -> None:
    orch = Orchestrator([FakePlugin([])], lab_scope(), resolver=lab_resolver, checks=[Silent()])
    assert ("probe", Activity.ACTIVE) in orch.activities()


# --- the command line and the service ---------------------------------------------------------


def test_zues_plugins_lists_them(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["plugins"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == ["NAME", "KIND", "ACTIVITY", "READY", "SOURCE", "SUMMARY"]
    assert any(line.startswith("nuclei ") and " active " in line for line in out.splitlines())
    assert cli.main(["plugins", "--json"]) == 0
    names = [p["name"] for p in json.loads(capsys.readouterr().out)["plugins"]]
    assert {"nmap", "nuclei", "ssh-packages", "subfinder"} <= set(names)


def _scope(tmp_path: Path, text: str = "10.0.0.0/24\n") -> str:
    path = tmp_path / "scope.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    ("flags", "error"),
    [
        (["--check", "nope"], "unknown check plugin 'nope'"),
        (["--scanner", "nuclei"], "nuclei is a check plugin, not a scanner"),
    ],
)
def test_wrong_plugin_names_stop_before_scanning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str], error: str
) -> None:
    argv = ["scan", "10.0.0.5", "--scope", _scope(tmp_path), "--db", str(tmp_path / "r.db")]
    assert cli.main([*argv, *flags]) == 2
    assert error in capsys.readouterr().err


def test_a_refused_check_is_in_the_audit_trail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: FakePlugin([]))
    monkeypatch.setattr("zues_scan.plugins.registry.NucleiPlugin", lambda **_: NucleiLike())
    db = tmp_path / "r.db"
    argv = ["scan", "10.0.0.5", "--scope", _scope(tmp_path), "--db", str(db), "--nuclei"]

    assert cli.main(argv) == 3
    assert "nuclei (active) goes beyond" in capsys.readouterr().err
    with Storage(db) as store:
        [(_, event, _)] = store.audit_events()
    assert event.kind == "refused" and "@activity active" in event.detail["reason"]


def test_the_service_names_plugins(tmp_path: Path) -> None:
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    d = tmp_path.as_posix()
    path = tmp_path / "service.toml"
    path.write_text(
        f'[service]\ndb = "x.db"\n[[targets]]\nname = "web"\ntarget = "10.0.0.5"\n'
        f'scope = "{d}/scope.txt"\nchecks = ["nuclei", "exposed-git"]\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert spec_for(config, config.target("web"), "alice").checks == ["nuclei", "exposed-git"]
    path.write_text(path.read_text().replace('["nuclei", "exposed-git"]', '"nuclei"'))
    with pytest.raises(ConfigError, match="must be a list of plugin names"):
        load_config(path)


# --- the contract -------------------------------------------------------------------------------


class Scanner:
    name = "fake-scanner"
    activity = Activity.SCAN

    def __init__(self, ips: list[str], raw: bool = True) -> None:
        self.ips, self.with_raw = ips, raw

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "1"

    def scan(self, target: ScanTarget) -> ScanResult:
        raw = [RawOutput(self.name, "text", (self.name,), "out")] if self.with_raw else []
        return ScanResult(assets=[Asset(host=ip, ip=ip) for ip in self.ips], raw=raw)


def test_a_good_scanner_keeps_the_contract() -> None:
    contract.assert_ok(contract.check_scanner(Scanner(["10.0.0.5"]), PLAN))


def test_contract_breaches_are_named() -> None:
    problems = contract.check_scanner(Scanner(["10.0.0.9"], raw=False), PLAN)
    assert problems == [
        "it reported 10.0.0.9, which it was not asked to scan",
        "it kept no raw output: the tool's own output is the evidence of a run",
    ]

    class Careless(Silent):
        def version(self) -> str | None:
            raise RuntimeError("no binary")

        def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
            stray = Asset(
                host="8.8.8.8", ip="8.8.8.8", findings=[Finding(asset="8.8.8.8", title="x")]
            )
            return ScanResult(assets=[stray], raw=[RawOutput("x", "t", ("x",), "")])

    problems = contract.check_check(Careless(), PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5")])
    assert any("does not say how far it goes" in p for p in problems)
    assert any("version() raised RuntimeError" in p for p in problems)
    assert "it reported 8.8.8.8: a check may only report on hosts it was given" in problems
    with pytest.raises(AssertionError, match="plugin contract broken"):
        contract.assert_ok(problems)


def test_a_discovery_plugin_stays_under_its_domain() -> None:
    class Finder:
        name = "finder"
        activity = Activity.PASSIVE

        def is_available(self) -> bool:
            return True

        def version(self) -> str | None:
            return None

        def discover(self, domain: str) -> DiscoveryResult:
            raw = [RawOutput("finder", "text", ("finder",), "")]
            return DiscoveryResult(names=["www.example.com", "evil.org"], raw=raw)

    assert contract.check_discovery(Finder(), "example.com") == [
        "it returned names outside example.com: evil.org"
    ]


# --- the example plugin package ---------------------------------------------------------------


@pytest.fixture
def example(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(EXAMPLE))
    sys.modules.pop("zues_exposed_git", None)
    import zues_exposed_git

    return zues_exposed_git


@pytest.fixture
def site(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    """A local web server serving `tmp_path`."""

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(tmp_path), **kwargs)

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], tmp_path
    server.shutdown()


def test_the_example_plugin_finds_an_exposed_repository(
    example: Any, site: tuple[int, Path]
) -> None:
    port, root = site
    web = Service(port=port, name="http")
    assets = [Asset(host="127.0.0.1", ip="127.0.0.1", services=[web])]
    plan = ScanTarget("127.0.0.1", ("127.0.0.1",))
    plugin = example.PLUGIN.factory(PluginContext())

    assert contract.check_spec(example.PLUGIN) == []
    clean = plugin.check(plan, assets)
    assert clean.assets == [] and "-> 404" in clean.raw[0].content

    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    contract.assert_ok(contract.check_check(plugin, plan, assets))
    [asset] = plugin.check(plan, assets).assets
    [finding] = asset.findings
    assert (finding.title, finding.rule_id, finding.service) == (
        "Git repository exposed over HTTP",
        "exposed-git",
        web,
    )
    assert "ref: refs/heads/main" in finding.evidence


def test_the_example_plugin_registers_through_its_entry_point(example: Any) -> None:
    loaded = registry.load(lambda: [Entry("exposed-git", example.PLUGIN, "zues-exposed-git")])
    spec = loaded.get("exposed-git", "check")
    assert (spec.activity, spec.source) == (Activity.ACTIVE, "zues-exposed-git")
    text = (EXAMPLE / "pyproject.toml").read_text(encoding="utf-8")
    assert '[project.entry-points."zues_scan.plugins"]' in text
    assert 'exposed-git = "zues_exposed_git:PLUGIN"' in text
