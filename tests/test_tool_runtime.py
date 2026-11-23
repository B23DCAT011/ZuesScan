"""How nuclei and subfinder run for real: pinned templates, isolated state, time limits,
failures that must not cost the port scan, and discovery that can return thousands."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, fake_resolver, lab_resolver, lab_scope

from zues_scan import cli
from zues_scan.cve import LocalCveSource
from zues_scan.orchestrator import Orchestrator, RunStatus
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.plugins.nuclei import NucleiPlugin, network_target, templates_version
from zues_scan.plugins.subfinder import SubfinderPlugin
from zues_scan.schema import Asset, Confidence, RawOutput, ScanTarget, Service
from zues_scan.scope import Scope
from zues_scan.server.config import ConfigError, load_config
from zues_scan.server.jobs import spec_for

SAMPLE = (Path(__file__).parent / "data" / "nuclei_sample.jsonl").read_text(encoding="utf-8")
APACHE = Service(port=8080, name="http", product="Apache httpd", version="2.4.49")
SSH = Service(port=22, name="ssh", product="OpenSSH", version="7.5")
PLAN = ScanTarget("10.0.0.5", ("10.0.0.5",))
TERRAPIN = (
    '{"template-id":"CVE-2023-48795","info":{"name":"OpenSSH Terrapin Attack",'
    '"severity":"medium","classification":{"cve-id":["cve-2023-48795"],"cvss-score":5.9}},'
    '"type":"javascript","host":"10.0.0.5:22","port":"22","ip":"10.0.0.5",'
    '"matched-at":"10.0.0.5:22"}\n'
)


@pytest.fixture
def templates(tmp_path: Path) -> Path:
    """A pinned templates directory, as the Docker image has it."""
    folder = tmp_path / "nuclei-templates"
    (folder / "http").mkdir(parents=True)
    (folder / ".nuclei-ignore").write_text("tags:\n  - dos\n", encoding="utf-8")
    (folder / ".zues-version").write_text("10.5.2\n", encoding="utf-8")
    return folder


def fake_nuclei(
    monkeypatch: pytest.MonkeyPatch, outcome: object, seen: list[dict[str, Any]]
) -> None:
    """`subprocess.run` answering like nuclei; records what each call got."""

    def run(command: list[str], **kwargs: Any) -> object:
        env = kwargs.get("env")
        call: dict[str, Any] = {"command": command, "input": kwargs.get("input"), "env": env}
        if env is not None:  # what nuclei finds in its configuration directory
            config = Path(env["NUCLEI_CONFIG_DIR"])
            call["ignore"] = (config / ".nuclei-ignore").read_text(encoding="utf-8")
        seen.append(call)
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(command, 0, stdout=str(outcome), stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nuclei")
    monkeypatch.setattr(subprocess, "run", run)


# --- nuclei: what it is given -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "service", "target"),
    [
        ("10.0.0.5", SSH, "10.0.0.5:22"),
        ("2001:db8::5", SSH, "[2001:db8::5]:22"),
        ("10.0.0.5", Service(port=6379, name="redis"), "10.0.0.5:6379"),
        ("10.0.0.5", APACHE, None),  # a web service is checked by URL
        ("10.0.0.5", Service(port=53, protocol="udp", name="domain"), None),
        ("10.0.0.5", Service(port=22, state="filtered"), None),
    ],
)
def test_network_targets(ip: str, service: Service, target: str | None) -> None:
    assert network_target(ip, service) == target


def test_signed_templates_only_and_no_informational_noise(templates: Path) -> None:
    command = NucleiPlugin(templates=str(templates)).command(None)
    assert "-dut" in command  # an edited or planted template does not run
    assert command[command.index("-es") + 1] == "info"
    assert command[command.index("-t") + 1] == str(templates)
    for risky in ("-code", "-headless", "-lfa", "-dast", "-ut"):
        assert risky not in command
    assert "-t" not in NucleiPlugin().command(None)  # nuclei's own templates otherwise


def test_pinned_templates_run_in_a_fresh_configuration(
    monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    seen: list[dict[str, Any]] = []
    fake_nuclei(monkeypatch, TERRAPIN, seen)

    result = NucleiPlugin(templates=str(templates)).check(
        PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH])]
    )

    [call] = seen
    env = call["env"]
    assert env["HOME"] == env["USERPROFILE"] and Path(env["NUCLEI_CONFIG_DIR"]).parent == Path(
        env["HOME"]
    )
    assert call["ignore"] == "tags:\n  - dos\n"  # the templates' default exclusions
    assert not Path(env["HOME"]).exists()  # nothing left behind
    assert call["input"] == "10.0.0.5:22\n"
    assert call["command"][-2:] == ["-pt", "javascript,tcp,ssl"]  # not 11,000 HTTP templates
    [asset] = result.assets
    [finding] = asset.findings
    assert (finding.cve, finding.confidence) == ("CVE-2023-48795", Confidence.CONFIRMED)
    assert finding.service is SSH and finding.rule_id == "nuclei:CVE-2023-48795"


def test_without_pinned_templates_nuclei_keeps_its_own_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []
    fake_nuclei(monkeypatch, "", seen)
    NucleiPlugin().check(PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH])])
    assert seen[0]["env"] is None


def test_the_version_names_the_templates(monkeypatch: pytest.MonkeyPatch, templates: Path) -> None:
    def run(command: list[str], **kwargs: Any) -> object:
        return subprocess.CompletedProcess(
            command, 0, stdout="", stderr="[INF] Nuclei Engine Version: v3.11.1\n"
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert NucleiPlugin(templates=str(templates)).version() == "3.11.1 (templates 10.5.2)"
    assert NucleiPlugin().version() == "3.11.1"
    assert templates_version(str(templates.parent)) is None


def test_missing_templates_are_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_nuclei(monkeypatch, "", [])
    with pytest.raises(ScanError, match="nuclei templates not found"):
        NucleiPlugin(templates=str(tmp_path / "nope")).check(
            PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH])]
        )


# --- nuclei: time limits ------------------------------------------------------------------------


def test_out_of_time_keeps_what_was_found(monkeypatch: pytest.MonkeyPatch) -> None:
    stopped = subprocess.TimeoutExpired("nuclei", 5, output=TERRAPIN.encode(), stderr=b"[WRN]")
    fake_nuclei(monkeypatch, stopped, [])

    result = NucleiPlugin(timeout=5).check(
        PLAN, [Asset(host="10.0.0.5", ip="10.0.0.5", services=[SSH])]
    )

    assert result.incomplete
    assert result.assets[0].findings[0].cve == "CVE-2023-48795"  # found before the limit
    assert result.raw[0].content == TERRAPIN
    assert "stopped after its time limit (5s)" in result.notes[0]


def test_one_budget_for_the_whole_check(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []
    fake_nuclei(monkeypatch, "", seen)
    clock = iter([0.0, 1.0, 100.0])  # the deadline is set, run 1 starts, run 2 is too late
    assets = [
        Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE]),
        Asset(host="www.example.com", ip="10.0.0.7", services=[APACHE], names=["www.example.com"]),
    ]

    plugin = NucleiPlugin(timeout=60)
    plugin.clock = lambda: next(clock)
    result = plugin.check(PLAN, assets)

    assert len(seen) == 1 and result.incomplete
    assert result.notes == ["not checked, out of time: http://10.0.0.7:8080 as www.example.com"]


# --- in the pipeline ----------------------------------------------------------------------------


class Check:
    name = "nuclei"

    def __init__(self, result: ScanResult | None = None, error: ScanError | None = None) -> None:
        self.result, self.error = result or ScanResult(), error

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "3.11.1 (templates 10.5.2)"

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        if self.error is not None:
            raise self.error
        return self.result


def _run(check: Check, cve: bool = False) -> Any:
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[APACHE])])
    orch = Orchestrator(
        [scanner],
        lab_scope("@activity active"),
        resolver=lab_resolver,
        checks=[check],
        cve_source=LocalCveSource() if cve else None,
    )
    return orch.run("10.0.0.5")


def test_a_failing_check_keeps_the_port_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    output = RawOutput("nuclei", "nuclei-jsonl", ("nuclei",), "", stderr="panic")
    run = _run(Check(error=ScanError("nuclei exited with code 2", plugin="nuclei", output=output)))

    assert run.status == RunStatus.PARTIAL
    assert run.assets[0].services == [APACHE]  # what nmap found is kept
    assert "nuclei failed, its checks are missing: nuclei exited with code 2" in run.notes
    assert output in run.raw_outputs


def test_an_incomplete_check_makes_the_run_partial() -> None:
    run = _run(Check(ScanResult(incomplete=True, notes=["stopped after its time limit"])))
    assert run.status == RunStatus.PARTIAL
    assert "nuclei: stopped after its time limit" in run.notes
    assert run.tool_versions["nuclei"] == "3.11.1 (templates 10.5.2)"


def test_an_observed_cve_keeps_the_curated_facts_of_the_database() -> None:
    hits = NucleiPlugin.parse_jsonl(SAMPLE)
    observed = [Asset(host=ip, ip=ip, findings=[f]) for ip, f in hits if f.cve]
    for asset in observed:  # nuclei saw it on the Apache port
        for f in asset.findings:
            f.service = APACHE

    run = _run(Check(ScanResult(assets=observed)), cve=True)

    [cve] = [f for f in run.assets[0].findings if f.cve == "CVE-2021-41773"]
    assert cve.confidence == Confidence.CONFIRMED  # seen, not inferred
    assert cve.rule_id == "nuclei:CVE-2021-41773"
    assert cve.kev_added == "2021-11-03"  # from the database: the template has no date
    assert cve.evidence.startswith("nuclei template CVE-2021-41773 matched")
    assert "\nAlso: " in cve.evidence  # the version match is not lost either


# --- discovery at scale -------------------------------------------------------------------------


class Finder:
    name = "subfinder"

    def __init__(self, names: list[str]) -> None:
        self.names = names

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "2.17.0"

    def discover(self, domain: str) -> Any:
        from zues_scan.plugins.base import DiscoveryResult

        return DiscoveryResult(names=list(self.names))


SCOPE = Scope.from_entries(["example.com", "*.example.com", "10.0.0.0/24"])


def test_only_the_closest_names_are_considered() -> None:
    names = ["a.b.c.example.com", "www.example.com", "zz.example.com", "x.y.example.com"]
    dns = fake_resolver({n: ["10.0.0.9"] for n in [*names, "example.com"]})
    scanner = FakePlugin([])
    run = Orchestrator(
        [scanner], SCOPE, resolver=dns, discovery=[Finder(names)], discover_limit=2
    ).run("example.com")

    [plan] = scanner.seen
    assert {n for n, _ in plan.names} == {"example.com", "www.example.com", "zz.example.com"}
    assert run.notes[0] == (
        "discovery: 4 name(s) found, only the 2 closest to example.com considered "
        "(limit 2); all are in the raw output"
    )


def test_names_that_only_match_a_wildcard_record_are_dropped() -> None:
    def dns(name: str) -> list[str]:
        if name == "real.example.com":
            return ["10.0.0.7"]
        return ["10.0.0.9"]  # *.example.com answers everything else

    plan, skipped = SCOPE.plan_discovered(
        "example.com", ["real.example.com", "junk1.example.com", "junk2.example.com"], dns
    )

    assert {n for n, _ in plan.names} == {"example.com", "real.example.com"}
    assert [n for n, _ in skipped] == ["junk1.example.com", "junk2.example.com"]
    assert "wildcard DNS record" in skipped[0][1]


def test_thousands_of_rejected_names_make_a_short_summary() -> None:
    names = [f"h{i}.example.com" for i in range(25)]
    dns = fake_resolver({"example.com": ["10.0.0.5"], **{n: ["203.0.113.1"] for n in names}})
    run = Orchestrator([FakePlugin([])], SCOPE, resolver=dns, discovery=[Finder(names)]).run(
        "example.com"
    )
    rejected = [n for n in run.notes if n.startswith("not scanned:")]
    assert len(rejected) == 21
    assert rejected[-1] == "not scanned: 5 more name(s), for the same kinds of reason"


# --- subfinder -----------------------------------------------------------------------------------


def test_subfinder_reads_the_configured_keys_in_a_fresh_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keys = tmp_path / "subfinder.yaml"
    keys.write_text("crtsh: []\n", encoding="utf-8")
    seen: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> object:
        seen.append({"command": command, "home": kwargs["env"]["HOME"]})
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/subfinder")
    monkeypatch.setattr(subprocess, "run", run)
    SubfinderPlugin(provider_config=str(keys)).discover("example.com")

    [call] = seen
    assert call["command"][-2:] == ["-pc", str(keys)]
    assert not Path(call["home"]).exists()


def test_subfinder_falls_back_to_the_users_own_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert "-pc" not in SubfinderPlugin().command("example.com")
    own = tmp_path / ".config" / "subfinder" / "provider-config.yaml"
    own.parent.mkdir(parents=True)
    own.write_text("", encoding="utf-8")
    assert SubfinderPlugin().command("example.com")[-2:] == ["-pc", str(own)]


# --- configuration ------------------------------------------------------------------------------


def test_the_service_config_names_the_tools(tmp_path: Path) -> None:
    (tmp_path / "scope.txt").write_text("*.example.com\n", encoding="utf-8")
    d = tmp_path.as_posix()
    path = tmp_path / "service.toml"
    path.write_text(
        f'[service]\ndb = "x.db"\nnuclei_templates = "/opt/nuclei-templates"\n'
        f'subfinder_config = "/config/subfinder.yaml"\n'
        f'[[targets]]\nname = "web"\ntarget = "example.com"\nscope = "{d}/scope.txt"\n'
        "discover = true\ndiscover_limit = 300\nnuclei = true\n",
        encoding="utf-8",
    )
    config = load_config(path)
    spec = spec_for(config, config.target("web"), "alice")
    assert spec.nuclei_templates == "/opt/nuclei-templates"
    assert spec.subfinder_config == "/config/subfinder.yaml"
    assert spec.discover_limit == 300

    path.write_text(path.read_text().replace("300", "0"), encoding="utf-8")
    with pytest.raises(ConfigError, match="discover_limit must be a whole number"):
        load_config(path)


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        (["--nuclei", "--nuclei-templates", "missing-dir"], "nuclei templates not found"),
        (["--subfinder-config", "missing.yaml"], "subfinder config not found"),
        (["--discover-limit", "0"], "--discover-limit must be at least 1"),
    ],
)
def test_bad_tool_settings_stop_before_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    error: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    scanner = FakePlugin([])
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: scanner)
    (tmp_path / "scope.txt").write_text("example.com\n*.example.com\n", encoding="utf-8")
    argv = ["scan", "example.com", "--scope", "scope.txt", "--db", "r.db", "--discover", *extra]
    assert cli.main(argv) == 2
    assert error in capsys.readouterr().err
    assert scanner.seen == [] and not (tmp_path / "r.db").exists()


def test_the_image_sets_the_templates_by_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, templates: Path
) -> None:
    made: list[dict[str, Any]] = []

    class Made(Check):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__()
            made.append(kwargs)

    monkeypatch.setenv("ZUES_NUCLEI_TEMPLATES", str(templates))
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr("zues_scan.plugins.registry.NmapPlugin", lambda **_: FakePlugin([]))
    monkeypatch.setattr("zues_scan.plugins.registry.NucleiPlugin", Made)
    scope = tmp_path / "scope.txt"
    scope.write_text("@activity active\n10.0.0.0/24\n", encoding="utf-8")
    argv = ["scan", "10.0.0.5", "--scope", str(scope), "--db", str(tmp_path / "r.db"), "--nuclei"]
    cli.main(argv)
    assert made[0]["templates"] == str(templates)


# --- check_rate: requests of active checks, apart from nmap's packets ---------------------------


def test_check_rate_is_its_own_setting() -> None:
    from zues_scan.profiles import BUILTIN, ProfileError, override

    full = BUILTIN["full"]
    assert NucleiPlugin(full).rate == 50  # neither set: the cautious default
    assert NucleiPlugin(override(full, {"max_rate": 200})).rate == 200  # as before
    fast_checks = override(full, {"check_rate": 300})
    assert NucleiPlugin(fast_checks).rate == 300
    assert fast_checks.max_rate is None  # nmap is not slowed down by it
    assert "checks max 300 req/s" in fast_checks.summary()
    with pytest.raises(ProfileError, match="check_rate must be a whole number 1-10000"):
        override(full, {"check_rate": 0})


def test_the_lab_profile_scans_fast_without_capping_nmap() -> None:
    from zues_scan.profiles import load_profiles

    lab = load_profiles(Path(__file__).parent.parent / "lab" / "profiles.toml")["lab"]
    assert (lab.ports, lab.traceroute, lab.max_rate, lab.check_rate) == ("-", True, None, 300)
    assert "--max-rate" not in lab.nmap_args()
