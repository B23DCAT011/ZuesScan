"""Tests for the authenticated package check (Debian packages vs the security tracker)."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_resolver, lab_scope

from reconkit import cli, debian
from reconkit.cve import LocalCveSource
from reconkit.cve.cache import CveCache, refresh_debian
from reconkit.debian import compare_versions, iter_tracker, parse_remote, verdict
from reconkit.orchestrator import Orchestrator
from reconkit.plugins.base import CheckPlugin
from reconkit.plugins.ssh_packages import (
    CredentialError,
    SshCredential,
    SshPackagesPlugin,
    load_credentials,
)
from reconkit.schema import Asset, Confidence, ScanTarget, Service
from reconkit.scope import Activity

OS_RELEASE = (
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
    'VERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian\n'
)
DPKG = (
    "openssh-server\t1:9.2p1-2+deb12u2\topenssh\t1:9.2p1-2+deb12u2\n"
    "openssh-client\t1:9.2p1-2+deb12u2\topenssh\t1:9.2p1-2+deb12u2\n"
    "libssl3:amd64\t3.0.15-1~deb12u1\topenssl\t3.0.15-1~deb12u1\n"
    "bash\t5.2.15-2+b7\tbash (5.2.15-2)\t5.2.15-2\n"
    "removed-pkg\t\t\t\n"
)
REMOTE = OS_RELEASE + debian.SEPARATOR + "\n" + DPKG
TRACKER = {
    "openssh": {
        # As the real tracker has them for bookworm (2026-11-22): Terrapin fixed in
        # deb12u2, regreSSHion in deb12u3.
        "CVE-2023-48795": {
            "description": "Terrapin",
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "1:9.2p1-2+deb12u2",
                    "urgency": "not yet assigned",
                },
                "bullseye": {"status": "resolved", "fixed_version": "1:8.4p1-5+deb11u3"},
            },
        },
        "CVE-2024-6387": {
            "description": "regreSSHion",
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "1:9.2p1-2+deb12u3",
                    "urgency": "not yet assigned",
                }
            },
        },
        "CVE-2016-20012": {
            "description": "user enum",
            "releases": {"bookworm": {"status": "open", "urgency": "unimportant"}},
        },
        "TEMP-0000000-ABCDEF": {"releases": {"bookworm": {"status": "open"}}},
    },
    "openssl": {
        "CVE-2014-0160": {  # Heartbleed: never in bookworm
            "description": "heartbleed",
            "releases": {
                "bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "high"}
            },
        }
    },
    "nginx": {
        "CVE-2021-23017": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0"}}}
    },
}
TRACKER_TEXT = json.dumps(TRACKER, indent=1)

# --- Debian versions -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("1.0~rc1-1", "1.0-1"),  # ~ sorts before the release
        ("1.0-1", "1.0-1+deb12u1"),  # a security update
        ("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3"),
        ("2.4-1", "2.30-1"),  # numbers, not text
        ("9.9", "1:0.1"),  # the epoch wins
        ("1.0", "1.0a"),
        ("1.0a", "1.0+"),  # letters before symbols
        ("3.0.15-1~deb12u1", "3.0.15-1"),  # a backport sorts before the release it backports
        ("1.2.3", "1.2.3-0.1"),
    ],
)
def test_versions_sort_like_dpkg(low: str, high: str) -> None:
    assert compare_versions(low, high) == -1
    assert compare_versions(high, low) == 1


@pytest.mark.parametrize(("a", "b"), [("1.0", "1.0"), ("0:1.0-1", "1.0-1"), ("1.00", "1.0")])
def test_equal_versions(a: str, b: str) -> None:
    assert compare_versions(a, b) == 0


def test_remote_answer_is_read() -> None:
    os_release, packages = parse_remote(REMOTE)
    assert (os_release.id, os_release.codename, os_release.version_id) == (
        "debian",
        "bookworm",
        "12",
    )
    assert [(p.name, p.source, p.source_version) for p in packages] == [
        ("openssh-server", "openssh", "1:9.2p1-2+deb12u2"),
        ("openssh-client", "openssh", "1:9.2p1-2+deb12u2"),
        ("libssl3", "openssl", "3.0.15-1~deb12u1"),
        ("bash", "bash", "5.2.15-2"),
    ]
    with pytest.raises(ValueError, match="no package list"):
        parse_remote(OS_RELEASE)


def test_tracker_is_read_package_by_package_for_the_chosen_releases() -> None:
    entries = list(iter_tracker(TRACKER_TEXT, {"bookworm"}))
    assert {(e.source, e.cve) for e in entries} == {
        ("openssh", "CVE-2023-48795"),
        ("openssh", "CVE-2024-6387"),
        ("openssh", "CVE-2016-20012"),
        ("openssl", "CVE-2014-0160"),
        ("nginx", "CVE-2021-23017"),
    }  # no TEMP- id, no bullseye row
    with pytest.raises(ValueError):
        list(iter_tracker("[1, 2]", {"bookworm"}))


def test_verdicts() -> None:
    entries = {e.cve: e for e in iter_tracker(TRACKER_TEXT, {"bookworm"})}
    installed = "1:9.2p1-2+deb12u2"
    assert verdict(installed, entries["CVE-2024-6387"]) == "fixed in 1:9.2p1-2+deb12u3: upgrade"
    assert verdict(installed, entries["CVE-2023-48795"]) is None  # same version as the fix
    assert verdict("3.0.15-1~deb12u1", entries["CVE-2014-0160"]) is None  # never affected
    assert verdict(installed, entries["CVE-2016-20012"]) == "no fix released yet for this release"


# --- the plugin ------------------------------------------------------------------------------


@pytest.fixture
def cache(tmp_path: Path) -> Iterator[CveCache]:
    with CveCache(tmp_path / "cve.db", create=True) as c:
        refresh_debian(
            c, {"bookworm"}, fetch=lambda url: TRACKER_TEXT.encode(), now=lambda: datetime.now(UTC)
        )
        yield c


def _credential(tmp_path: Path) -> SshCredential:
    key, known = tmp_path / "id_ed25519", tmp_path / "known_hosts"
    key.write_text("key", encoding="utf-8")
    known.write_text("10.0.0.5 ssh-ed25519 AAAA", encoding="utf-8")
    text = (
        '[[ssh]]\nhosts = ["10.0.0.0/24"]\nuser = "audit"\n'
        f"key = {json.dumps(str(key))}\nknown_hosts = {json.dumps(str(known))}\n"
    )
    path = tmp_path / "creds.toml"
    path.write_text(text, encoding="utf-8")
    (credential,) = load_credentials(path)
    return credential


def test_command_is_key_only_and_trusts_only_known_hosts(tmp_path: Path, cache: CveCache) -> None:
    plugin = SshPackagesPlugin([_credential(tmp_path)], cache)
    command = plugin.command(plugin.credentials[0], "10.0.0.5")
    assert {"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes"} <= set(command)
    assert command[-2:] == ["audit@10.0.0.5", debian.REMOTE_COMMAND]
    assert command[command.index("--") + 1] == "audit@10.0.0.5"  # no option can follow
    assert isinstance(plugin, CheckPlugin)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            '[[ssh]]\nhosts = ["10.0.0.0/24"]\nuser = "a"\npassword = "x"\n',
            "passwords are not supported",
        ),
        ('[[ssh]]\nhosts = ["10.0.0.0/24"]\nuser = "a"\n', "missing 'key'"),
        (
            '[[ssh]]\nhosts = ["nope"]\nuser = "a"\nkey = "k"\nknown_hosts = "k"\n',
            "does not appear",
        ),
        (
            '[[ssh]]\nhosts = ["10.0.0.0/24"]\nuser = "a b"\nkey = "k"\nknown_hosts = "k"\n',
            "invalid user",
        ),
        (
            '[[ssh]]\nhosts = ["10.0.0.0/24"]\nuser = "a"\nkey = "nope"\nknown_hosts = "nope"\n',
            "key file not found",
        ),
        ("[other]\n", r"no \[\[ssh\]\] entry"),
    ],
)
def test_bad_credentials_files(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "creds.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(CredentialError, match=message):
        load_credentials(path)


def test_assessment_of_one_host(tmp_path: Path, cache: CveCache) -> None:
    result = SshPackagesPlugin([_credential(tmp_path)], cache).assess("10.0.0.5", REMOTE)
    (asset,) = result.assets
    by_cve = {f.cve: f for f in asset.findings}
    assert set(by_cve) == {"CVE-2024-6387", "CVE-2016-20012"}
    regresshion = by_cve["CVE-2024-6387"]
    assert regresshion.title == "CVE-2024-6387 in openssh 1:9.2p1-2+deb12u2"
    assert regresshion.rule_id == "debian:openssh"
    assert regresshion.confidence == Confidence.FIRM
    assert regresshion.severity == "medium"  # urgency "not yet assigned"
    assert (
        "Debian security tracker (bookworm): resolved, fixed in 1:9.2p1-2+deb12u3"
        in regresshion.evidence
    )
    assert by_cve["CVE-2016-20012"].severity == "info"  # "unimportant" to Debian
    assert result.cleared["10.0.0.5"] == {"CVE-2023-48795", "CVE-2014-0160"}
    assert "3 packages" not in result.notes[0] and "4 packages checked" in result.notes[0]


def test_other_systems_and_missing_data_are_noted(tmp_path: Path, cache: CveCache) -> None:
    plugin = SshPackagesPlugin([_credential(tmp_path)], cache)
    ubuntu = REMOTE.replace("ID=debian", "ID=ubuntu")
    assert "only Debian is assessed" in plugin.assess("10.0.0.5", ubuntu).notes[0]
    trixie = REMOTE.replace("bookworm", "trixie")
    assert "run reconkit cve sync --debian trixie" in plugin.assess("10.0.0.5", trixie).notes[0]


def _fake_ssh(monkeypatch: pytest.MonkeyPatch, code: int, out: str) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(
            command, code, stdout=out, stderr="Host key verification failed." if code else ""
        )

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/ssh")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_check_logs_in_only_where_ssh_is_open_and_covered(
    tmp_path: Path, cache: CveCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_ssh(monkeypatch, 0, REMOTE)
    assets = [
        Asset(host="10.0.0.5", ip="10.0.0.5", services=[Service(port=22, name="ssh")]),
        Asset(host="10.0.0.7", ip="10.0.0.7", services=[Service(port=80, name="http")]),
        Asset(host="192.0.2.9", ip="192.0.2.9", services=[Service(port=22, name="ssh")]),
    ]
    result = SshPackagesPlugin([_credential(tmp_path)], cache).check(
        ScanTarget("x", ("10.0.0.0/24",)), assets
    )
    assert [c[-2] for c in calls] == ["audit@10.0.0.5"]  # no ssh on .7, no credential for 192.0.2.9
    assert result.raw[0].content == REMOTE and result.raw[0].format == "os-release+dpkg"


def test_failed_login_is_a_note(
    tmp_path: Path, cache: CveCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_ssh(monkeypatch, 255, "")
    assets = [Asset(host="10.0.0.5", ip="10.0.0.5", services=[Service(port=22, name="ssh")])]
    result = SshPackagesPlugin([_credential(tmp_path)], cache).check(
        ScanTarget("x", ("10.0.0.5",)), assets
    )
    assert result.assets == []
    assert "login failed, no package check (Host key verification failed.)" in result.notes[0]


# --- the backport case, end to end -----------------------------------------------------------


class PackageCheck:
    """Stands in for the SSH plugin: the installed OpenSSH carries CVE-2018-15473's fix."""

    name = "ssh-packages"
    activity = Activity.SCAN  # a read-only login, like the real one

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "9.5"

    def check(self, plan: ScanTarget, assets: list[Asset]) -> Any:
        from reconkit.plugins.base import ScanResult

        return ScanResult(cleared={"10.0.0.5": {"CVE-2018-15473"}})


def test_a_package_check_withdraws_the_banner_guess() -> None:
    banner = Service(port=22, name="ssh", product="OpenSSH", version="7.4p1 Debian 10+deb9u7")
    scanner = FakePlugin([Asset(host="10.0.0.5", ip="10.0.0.5", services=[banner])])
    orch = Orchestrator(
        [scanner],
        lab_scope(),
        cve_source=LocalCveSource(),
        resolver=lab_resolver,
        checks=[PackageCheck()],
    )
    run = orch.run("10.0.0.5")
    assert run.assets[0].findings == []  # the tentative CVE-2018-15473 match is gone
    assert "10.0.0.5: 1 version-based finding(s) withdrawn" in run.notes[-1]
    without = Orchestrator(
        [scanner], lab_scope(), cve_source=LocalCveSource(), resolver=lab_resolver
    )
    assert [f.cve for f in without.run("10.0.0.5").assets[0].findings] == ["CVE-2018-15473"]


# --- CLI -------------------------------------------------------------------------------------


def test_cli_credentials_need_the_cache(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.0/24\n", encoding="utf-8")
    argv = ["scan", "10.0.0.5", "--scope", str(scope), "--db", str(tmp_path / "d")]
    assert cli.main([*argv, "--credentials", str(tmp_path / "c.toml")]) == 2
    assert "--credentials needs --cve-cache" in capsys.readouterr().err


def test_cli_sync_debian(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from reconkit.cve import cache as cache_module
    from reconkit.cve.nvd import NvdClient

    monkeypatch.setattr(
        cli,
        "NvdClient",
        lambda api_key=None: NvdClient(
            fetch=lambda u, h: {"totalResults": 0, "vulnerabilities": []}
        ),
    )
    monkeypatch.setattr(
        cli,
        "refresh_debian",
        lambda c, r: cache_module.refresh_debian(c, r, fetch=lambda u: TRACKER_TEXT.encode()),
    )
    argv = [
        "cve",
        "sync",
        "--cache",
        str(tmp_path / "c.db"),
        "--no-kev",
        "--no-epss",
        "--debian",
        "bookworm",
    ]
    assert cli.main(argv) == 0
    assert "Debian security tracker (bookworm): 5 entries" in capsys.readouterr().out
