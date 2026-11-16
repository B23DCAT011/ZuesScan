"""Tests for the shared data model, focused on what a fingerprint means (G12)."""

import re

from reconkit.schema import FINGERPRINT_SCHEME, Asset, Finding, Service, Severity

SSH = Service(port=22, name="ssh", product="OpenSSH", version="7.4")


def _ssh_finding(**changes: object) -> Finding:
    fields: dict[str, object] = {
        "asset": "host.lab",
        "ip": "10.0.0.5",
        "title": "OpenSSH username enumeration",
        "severity": Severity.MEDIUM,
        "service": SSH,
        "cve": "CVE-2018-15473",
    }
    fields.update(changes)
    return Finding(**fields)  # type: ignore[arg-type]


def _fp(**changes: object) -> str:
    return _ssh_finding(**changes).compute_fingerprint()


def test_fingerprint_is_deterministic() -> None:
    assert _fp() == _fp()


def test_fingerprint_names_its_scheme() -> None:
    # Fingerprints of different schemes must never be compared: each says which
    # recipe made it.
    assert FINGERPRINT_SCHEME == 2
    assert re.fullmatch(r"v2:[0-9a-f]{64}", _fp())


def test_compute_fingerprint_sets_the_field() -> None:
    finding = _ssh_finding()
    assert finding.fingerprint == ""
    assert finding.compute_fingerprint() == finding.fingerprint


# --- what must NOT change the fingerprint ----------------------------------------


def test_rewording_the_finding_does_not_make_it_a_new_issue() -> None:
    # G12: fixing a typo in the CVE database used to turn every old issue into a
    # "new" one — and the old one into "fixed".
    assert _fp() == _fp(title="OpenSSH: valid usernames can be enumerated", description="reworded")


def test_fingerprint_ignores_volatile_fields() -> None:
    assert _fp(evidence="banner at 12:00:01, session 9f3c") == _fp(
        evidence="banner at 15:42:59, session a1b2",
        severity=Severity.HIGH,  # scores get revised
    )


def test_upgrade_to_another_vulnerable_version_is_the_same_open_issue() -> None:
    # 7.4 -> 7.5 and the CVE still applies: the issue was not fixed, and a "fixed"
    # ticket for it must be caught as a fake fix, not hidden behind a new fingerprint.
    upgraded = Service(port=22, name="ssh", product="OpenSSH", version="7.5")
    assert _fp() == _fp(service=upgraded)


def test_scanning_by_name_or_by_address_is_the_same_machine() -> None:
    assert _fp(asset="host.lab") == _fp(asset="10.0.0.5") == _fp(asset="other-name.lab")


def test_spelling_of_address_cve_and_protocol_does_not_matter() -> None:
    v6 = _fp(ip="2001:db8::1")
    assert v6 == _fp(ip="2001:DB8:0:0:0:0:0:1")
    assert _fp() == _fp(cve=" cve-2018-15473 ")
    assert _fp() == _fp(service=Service(port=22, protocol="TCP"))


# --- what MUST change the fingerprint --------------------------------------------


def test_different_machine_is_a_different_finding() -> None:
    # One name can front several machines: each has its own finding.
    assert _fp(ip="10.0.0.5") != _fp(ip="10.0.0.6")


def test_different_port_or_protocol_is_a_different_finding() -> None:
    assert _fp() != _fp(service=Service(port=2222))
    assert _fp() != _fp(service=Service(port=22, protocol="udp"))
    assert _fp() != _fp(service=None)


def test_different_cve_is_a_different_finding() -> None:
    assert _fp() != _fp(cve="CVE-2016-10009")


# --- findings that are not CVEs --------------------------------------------------


def test_rule_id_identifies_a_finding_without_cve() -> None:
    a = _fp(cve=None, rule_id="exposed-admin-panel", title="Admin panel exposed")
    b = _fp(cve=None, rule_id="exposed-admin-panel", title="Exposed administration panel")
    other = _fp(cve=None, rule_id="default-credentials", title="Admin panel exposed")
    assert a == b
    assert a != other


def test_cve_wins_over_rule_id() -> None:
    # Two tools finding the same CVE through different checks found the same issue.
    assert _fp(rule_id="nuclei-openssh-enum") == _fp(rule_id=None)


def test_finding_with_neither_cve_nor_rule_falls_back_to_its_title() -> None:
    a = _fp(cve=None, title="Weak  TLS configuration")
    assert a == _fp(cve=None, title="weak tls configuration")  # case and spacing only
    assert a != _fp(cve=None, title="Weak SSH configuration")


def test_asset_without_address_is_identified_by_name() -> None:
    assert _fp(ip=None, asset="Host.Lab.") == _fp(ip=None, asset="host.lab")
    assert _fp(ip=None, asset="host.lab") != _fp(ip=None, asset="other.lab")


def test_asset_defaults_are_independent() -> None:
    a = Asset(host="a.lab")
    b = Asset(host="b.lab")
    a.services.append(Service(port=80))
    assert b.services == []  # no shared mutable default
