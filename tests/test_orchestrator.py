"""Tests for the orchestrator pipeline."""

import pytest
from conftest import FakePlugin, fake_resolver, lab_asset, lab_resolver, lab_scope

from reconkit.cve import CveSource, LocalCveSource
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator, RunStatus
from reconkit.plugins.base import ScanError, ScannerPlugin
from reconkit.schema import Asset, Finding, Service
from reconkit.scope import ResolutionError, Resolver, Scope, ScopeError

OPENSSH_74 = Service(port=22, name="ssh", product="OpenSSH", version="7.4")


def _orch(
    plugins: list[ScannerPlugin],
    scope: Scope | None = None,
    cve_source: CveSource | None = None,
    resolver: Resolver = lab_resolver,
) -> Orchestrator:
    """An orchestrator over the lab scope, with DNS answered from a dict."""
    return Orchestrator(
        plugins=plugins, scope=scope or lab_scope(), cve_source=cve_source, resolver=resolver
    )


def test_refuses_out_of_scope_target() -> None:
    plugin = FakePlugin([])
    with pytest.raises(ScopeError):
        _orch([plugin]).run("evil.example.com")
    assert plugin.seen == []  # refused before any plugin was called


def test_collects_services_from_plugins() -> None:
    plugin = FakePlugin([lab_asset(Service(port=22, name="ssh"), Service(port=80, name="http"))])
    run = _orch([plugin]).run("scanme.lab")
    assert run.target == "scanme.lab"
    assert len(run.assets) == 1
    assert run.assets[0].host == "scanme.lab"
    assert run.assets[0].ip == "10.0.0.5"
    assert {s.port for s in run.assets[0].services} == {22, 80}


# --- scope gate: names are resolved once and plugins get addresses (G4) ----------


def test_plugin_is_given_the_resolved_addresses_not_the_name() -> None:
    plugin = FakePlugin([lab_asset()])
    run = _orch([plugin]).run("scanme.lab")
    (seen,) = plugin.seen
    assert seen.addresses == ("10.0.0.5",)
    assert seen.hostname == "scanme.lab"
    assert run.plan == seen  # the run records what was authorised


def test_refuses_name_that_resolves_outside_the_scope() -> None:
    # The name is allowlisted, but it points at a machine that is not ours.
    plugin = FakePlugin([])
    orch = _orch([plugin], resolver=fake_resolver({"scanme.lab": ["203.0.113.9"]}))
    with pytest.raises(ScopeError, match=r"resolves to 203\.0\.113\.9"):
        orch.run("scanme.lab")
    assert plugin.seen == []


def test_unresolvable_name_is_an_error_before_any_scan() -> None:
    plugin = FakePlugin([])
    orch = _orch([plugin], resolver=fake_resolver({}))
    with pytest.raises(ResolutionError):
        orch.run("scanme.lab")
    assert plugin.seen == []


def test_range_overlapping_denylist_is_scanned_with_exclusions() -> None:
    plugin = FakePlugin([lab_asset(host="10.0.0.5", ip="10.0.0.5")])
    _orch([plugin], scope=lab_scope("!10.0.0.1")).run("10.0.0.0/24")
    (seen,) = plugin.seen
    assert seen.addresses == ("10.0.0.0/24",)
    assert seen.exclude == ("10.0.0.1",)


def test_host_reported_outside_the_scope_is_dropped_and_recorded() -> None:
    # A tool that strays (or a discovery tool listing third-party hosts) must not
    # get out-of-scope machines into the results.
    plugin = FakePlugin(
        [
            lab_asset(Service(port=22), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(Service(port=22), host="10.0.0.1", ip="10.0.0.1"),  # denied
            lab_asset(Service(port=80), host="192.0.2.50", ip="192.0.2.50"),  # not allowed
        ]
    )
    run = _orch([plugin], scope=lab_scope("!10.0.0.1")).run("10.0.0.0/24")
    assert [a.ip for a in run.assets] == ["10.0.0.5"]
    assert run.out_of_scope == ["10.0.0.1", "192.0.2.50"]


# --- one asset per host (G1) -----------------------------------------------------


def test_range_target_yields_one_asset_per_host() -> None:
    # A range must not collapse into a single asset named after the range.
    plugin = FakePlugin(
        [
            lab_asset(Service(port=22), host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(Service(port=80), host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    run = _orch([plugin]).run("10.0.0.0/24")
    assert run.target == "10.0.0.0/24"
    ports_by_ip = {a.ip: [s.port for s in a.services] for a in run.assets}
    assert ports_by_ip == {"10.0.0.5": [22], "10.0.0.7": [80]}


def test_same_issue_on_two_hosts_gives_two_distinct_findings() -> None:
    # Two machines with the same vulnerable software are two findings.
    plugin = FakePlugin(
        [
            lab_asset(OPENSSH_74, host="10.0.0.5", ip="10.0.0.5"),
            lab_asset(OPENSSH_74, host="10.0.0.7", ip="10.0.0.7"),
        ]
    )
    run = _orch([plugin], cve_source=LocalCveSource()).run("10.0.0.0/24")
    findings = [f for a in run.assets for f in a.findings]
    assert [f.asset for f in findings] == ["10.0.0.5", "10.0.0.7"]
    assert len({f.fingerprint for f in findings}) == 2


def test_merges_what_two_plugins_report_for_the_same_host() -> None:
    ports = FakePlugin([lab_asset(Service(port=22, name="ssh"), Service(port=80, name="http"))])
    issue = Finding(asset="scanme.lab", title="exposed admin panel")
    checks = FakePlugin(
        [
            Asset(
                host="10.0.0.5",  # same machine, named differently by this tool
                ip="10.0.0.5",
                services=[Service(port=80, name="http-alt"), Service(port=443, name="https")],
                findings=[issue],
            )
        ]
    )
    run = _orch([ports, checks]).run("scanme.lab")

    assert len(run.assets) == 1
    asset = run.assets[0]
    assert asset.host == "scanme.lab"  # the first plugin's name for the host is kept
    assert [(s.port, s.name) for s in asset.services] == [
        (22, "ssh"),
        (80, "http"),  # already known: the second report of port 80 is not duplicated
        (443, "https"),
    ]
    assert asset.findings == [issue]


def test_assets_without_ip_are_matched_by_name() -> None:
    first = FakePlugin([Asset(host="scanme.lab")])
    second = FakePlugin([Asset(host="scanme.lab", ip="10.0.0.5")])
    run = _orch([first, second]).run("scanme.lab")
    assert [(a.host, a.ip) for a in run.assets] == [("scanme.lab", "10.0.0.5")]


# --- CVE stage -------------------------------------------------------------------


def test_cve_stage_produces_findings() -> None:
    run = _orch([FakePlugin([lab_asset(OPENSSH_74)])], cve_source=LocalCveSource()).run(
        "scanme.lab"
    )
    findings = run.assets[0].findings
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2018-15473"
    assert findings[0].asset == "scanme.lab"


def test_no_cve_source_means_no_findings() -> None:
    run = _orch([FakePlugin([lab_asset(OPENSSH_74)])]).run("scanme.lab")
    assert run.assets[0].findings == []


# --- fingerprints: one identity per issue, set in one place (G12) -----------------


def test_every_finding_is_fingerprinted_against_the_merged_asset() -> None:
    # A plugin names the host its own way and knows no address; the finding must
    # still be identified by the machine the orchestrator settled on.
    issue = Finding(asset="10.0.0.5", title="exposed admin panel", rule_id="admin-panel")
    checks = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", findings=[issue])])
    ports = FakePlugin([lab_asset(OPENSSH_74)])
    run = _orch([ports, checks], cve_source=LocalCveSource()).run("scanme.lab")

    findings = run.assets[0].findings
    assert {f.rule_id or f.cve for f in findings} == {"admin-panel", "CVE-2018-15473"}
    for finding in findings:
        assert (finding.asset, finding.ip) == ("scanme.lab", "10.0.0.5")
        assert finding.fingerprint.startswith("v2:")
        assert finding.fingerprint == finding.compute_fingerprint()


def test_scan_by_name_and_scan_by_address_give_the_same_fingerprint() -> None:
    # What `feat/diff` needs: Monday's range scan and Tuesday's scan of one name
    # must recognise the same issue.
    by_name = _orch([FakePlugin([lab_asset(OPENSSH_74)])], cve_source=LocalCveSource()).run(
        "scanme.lab"
    )
    by_address = _orch(
        [FakePlugin([lab_asset(OPENSSH_74, host="10.0.0.5")])], cve_source=LocalCveSource()
    ).run("10.0.0.5")
    assert by_name.assets[0].findings[0].fingerprint == by_address.assets[0].findings[0].fingerprint


def test_same_issue_reported_by_two_tools_is_one_finding() -> None:
    def cve_report() -> Finding:
        return Finding(
            asset="scanme.lab", title="tool wording", service=OPENSSH_74, cve="CVE-2018-15473"
        )

    first = FakePlugin(
        [Asset(host="scanme.lab", ip="10.0.0.5", services=[OPENSSH_74], findings=[cve_report()])]
    )
    second = FakePlugin([Asset(host="scanme.lab", ip="10.0.0.5", findings=[cve_report()])])
    run = _orch([first, second], cve_source=LocalCveSource()).run("scanme.lab")
    # Two plugins and the CVE stage all found CVE-2018-15473 on 22/tcp.
    assert [f.cve for f in run.assets[0].findings] == ["CVE-2018-15473"]


# --- plugin availability (G2) ----------------------------------------------------


def test_skips_unavailable_plugins() -> None:
    present = FakePlugin([lab_asset(Service(port=22))], available=True)
    missing = FakePlugin([lab_asset(Service(port=443))], available=False)
    run = _orch([present, missing]).run("scanme.lab")
    assert {s.port for s in run.assets[0].services} == {22}
    assert run.skipped_plugins == ["fake"]  # the result is flagged as partial


def test_no_available_plugin_is_an_error() -> None:
    missing = FakePlugin([lab_asset(Service(port=22))], available=False)
    with pytest.raises(NoPluginAvailableError, match="fake not installed"):
        _orch([missing]).run("scanme.lab")


def test_no_configured_plugin_is_an_error() -> None:
    with pytest.raises(NoPluginAvailableError, match="no scanner configured"):
        _orch([]).run("scanme.lab")


def test_scope_is_checked_before_plugin_availability() -> None:
    missing = FakePlugin([], available=False)
    with pytest.raises(ScopeError):
        _orch([missing]).run("evil.example.com")


# --- what a run records about itself (G14) ---------------------------------------


def test_run_records_status_and_scanner_versions() -> None:
    run = _orch([FakePlugin([lab_asset()], version="7.92")]).run("scanme.lab")
    assert run.status is RunStatus.COMPLETED
    assert run.error is None
    assert run.tool_versions == {"fake": "7.92"}


def test_run_with_a_skipped_scanner_is_partial() -> None:
    present = FakePlugin([lab_asset()])
    missing = FakePlugin([], available=False)
    missing.name = "nuclei"
    run = _orch([present, missing]).run("scanme.lab")
    assert run.status is RunStatus.PARTIAL
    assert run.skipped_plugins == ["nuclei"]
    assert run.tool_versions == {"fake": "1.0-fake"}  # only scanners that were started


def test_failed_run_describes_a_scanner_failure() -> None:
    error = ScanError("nmap exited with code 1", plugin="fake", stderr="requires root")
    orch = _orch([FakePlugin([], error=error, version="7.92")])
    with pytest.raises(ScanError) as caught:
        orch.run("scanme.lab")

    run = orch.failed_run("scanme.lab", "2026-01-01T00:00:00+00:00", caught.value)
    assert run.status is RunStatus.FAILED
    assert run.error == "nmap exited with code 1\nrequires root"
    assert run.failed_plugin == "fake"
    assert run.tool_versions == {"fake": "7.92"}
    assert run.started_at == "2026-01-01T00:00:00+00:00"
    assert run.assets == []  # never a result


def test_failed_run_describes_a_missing_scanner() -> None:
    orch = _orch([FakePlugin([], available=False)])
    with pytest.raises(NoPluginAvailableError) as caught:
        orch.run("scanme.lab")

    run = orch.failed_run("scanme.lab", "2026-01-01T00:00:00+00:00", caught.value)
    assert run.status is RunStatus.FAILED
    assert run.error == "no scanner available: fake not installed or not on PATH"
    assert run.failed_plugin is None
    assert run.skipped_plugins == ["fake"]
    assert run.tool_versions == {}
