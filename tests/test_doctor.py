"""`zues doctor`: what a machine can scan with, and the exact fix for what it cannot."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zues_scan import cli, doctor
from zues_scan.cve.cache import CveCache
from zues_scan.doctor import (
    ERROR,
    INFO,
    MISSING,
    OK,
    WARN,
    System,
    check_cve_cache,
    check_dns_resolvers,
    check_nmap,
    check_nmap_rights,
    check_providers,
    check_templates,
    install_hint,
    provider_keys,
)

DEBIAN = System("Linux", "debian", "Debian 13", euid=1000)
NOW = datetime(2026, 11, 23, tzinfo=UTC)


def capability(*bits: int) -> bytes:
    """A security.capability value (vfs_cap_data v2) with these permitted bits."""
    permitted = sum(1 << b for b in bits)
    return (0x02000001).to_bytes(4, "little") + permitted.to_bytes(4, "little") + bytes(12)


# --- how to install, per system -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "tool", "command"),
    [
        (DEBIAN, "nmap", "sudo apt install nmap"),
        (System("Linux", "ubuntu debian"), "ssh", "sudo apt install openssh-client"),
        (System("Linux", "rocky rhel centos fedora"), "nmap", "sudo dnf install nmap"),
        (System("Linux", "arch"), "nmap", "sudo pacman -S nmap"),
        (System("Linux", "alpine"), "nmap", "sudo apk add nmap"),
        (System("Linux", "opensuse-leap suse opensuse"), "nmap", "sudo zypper install nmap"),
        (
            System("Linux", "gentoo"),
            "nmap",
            "install nmap with your distribution's package manager",
        ),
        (System("Darwin"), "nmap", "brew install nmap"),
    ],
)
def test_system_packages_are_left_to_the_user_with_the_right_command(
    system: System, tool: str, command: str
) -> None:
    assert install_hint(tool, system) == command


def test_windows_gets_winget_with_npcap() -> None:
    hint = install_hint("nmap", System("Windows"))
    assert hint.startswith("winget install Insecure.Nmap") and "Npcap" in hint


def test_projectdiscovery_tools_need_no_package_manager() -> None:
    assert install_hint("nuclei", DEBIAN).startswith("zues tools install nuclei")


# --- nmap ---------------------------------------------------------------------------------------


def test_nmap_is_required() -> None:
    missing = check_nmap(None, None, DEBIAN)
    assert (missing.status, missing.hint, missing.blocking) == (
        MISSING,
        "sudo apt install nmap",
        True,
    )
    found = check_nmap("/usr/bin/nmap", "7.95", DEBIAN)
    assert (found.status, found.detail, found.blocking) == (OK, "7.95 (/usr/bin/nmap)", False)


def test_nmap_installed_but_not_on_path_on_windows(tmp_path: Path) -> None:
    (tmp_path / "Nmap").mkdir()
    (tmp_path / "Nmap" / "nmap.exe").write_bytes(b"MZ")
    check = check_nmap(None, None, System("Windows", env={"ProgramFiles(x86)": str(tmp_path)}))
    assert check.status == WARN and "not on PATH" in check.detail
    assert "new terminal" in (check.hint or "")


def test_raw_socket_rights_on_linux() -> None:
    root = check_nmap_rights("/usr/bin/nmap", System("Linux", euid=0), None)
    assert (root.status, root.detail) == (OK, "running as root")

    privileged = System("Linux", euid=10001, env={"NMAP_PRIVILEGED": "1"})
    assert check_nmap_rights("/usr/bin/nmap", privileged, capability(13)).status == OK

    unused = check_nmap_rights("/usr/bin/nmap", System("Linux", euid=10001), capability(13))
    assert unused.status == WARN and unused.hint == "export NMAP_PRIVILEGED=1"

    other_cap = check_nmap_rights("/usr/bin/nmap", privileged, capability(12))  # NET_ADMIN
    assert other_cap.status == WARN
    assert other_cap.hint is not None and other_cap.hint.startswith(
        "sudo setcap cap_net_raw+eip /usr/bin/nmap"
    )
    assert "TCP connect scan" in other_cap.detail


def test_raw_socket_rights_elsewhere(tmp_path: Path) -> None:
    mac = check_nmap_rights("/opt/homebrew/bin/nmap", System("Darwin", euid=501), None)
    assert mac.status == WARN and mac.hint == "run ZuesScan with sudo"
    no_npcap = check_nmap_rights(
        "nmap.exe", System("Windows", env={"SystemRoot": str(tmp_path)}), None
    )
    assert no_npcap.status == WARN and "npcap.com" in (no_npcap.hint or "")
    (tmp_path / "System32" / "Npcap").mkdir(parents=True)
    npcap = check_nmap_rights(
        "nmap.exe", System("Windows", env={"SystemRoot": str(tmp_path)}), None
    )
    assert npcap.status == OK


# --- nuclei templates, subfinder keys, CVE data -------------------------------------------------


def test_templates(tmp_path: Path) -> None:
    pinned = tmp_path / "tpl"
    pinned.mkdir()
    assert check_templates(str(pinned), "10.5.2", tmp_path).status == OK
    assert check_templates(str(tmp_path / "gone"), None, tmp_path).status == ERROR
    assert check_templates(None, None, tmp_path).status == WARN  # would download mid-scan
    (tmp_path / "nuclei-templates").mkdir()
    own = check_templates(None, None, tmp_path)
    assert own.status == INFO and "not pinned" in own.detail


@pytest.mark.parametrize(
    ("text", "keys"),
    [
        ("bevigil: []\ncensys: []\n", 0),  # what subfinder writes on its first run
        ("censys:\n  - id:secret\nchaos: [abc]\nshodan:\n  - k1\n  - k2\nzoomeye: []\n", 3),
        ("# comment\nvirustotal:\n  - key\n", 1),
    ],
)
def test_provider_keys_are_counted(text: str, keys: int) -> None:
    assert provider_keys(text) == keys


def test_providers(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("crtsh: []\n", encoding="utf-8")
    assert check_providers(str(empty)).status == INFO
    keys = tmp_path / "keys.yaml"
    keys.write_text("chaos:\n  - abc\n", encoding="utf-8")
    assert check_providers(str(keys)).detail.startswith("1 source(s) with API keys")
    assert check_providers(None).status == INFO


def test_cve_data(tmp_path: Path) -> None:
    path = tmp_path / "cve.db"
    assert check_cve_cache(str(path), NOW).status == INFO  # the bundled seed only
    with CveCache(path, create=True) as cache:
        cache.mark_synced("all", NOW - timedelta(days=2), 0)
    fresh = check_cve_cache(str(path), NOW)
    assert fresh.status == OK and "synced 2 day(s) ago" in fresh.detail
    stale = check_cve_cache(str(path), NOW + timedelta(days=10))
    assert stale.status == WARN and stale.hint == f"zues cve sync --cache {path}"


# --- the command --------------------------------------------------------------------------------


def test_not_ready_without_nmap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(doctor, "_windows_nmap", lambda system: None)
    monkeypatch.setattr("zues_scan.tools._windows_install", lambda name: None)

    assert cli.main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("ZuesScan ")
    assert "not ready: nmap must be fixed before any scan" in out

    assert cli.main(["doctor", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ready"] is False
    nmap = next(c for c in data["checks"] if c["name"] == "nmap")
    assert (nmap["status"], nmap["required"]) == ("missing", True)


def test_a_service_config_is_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "service.toml"
    bad.write_text("[service]\n", encoding="utf-8")
    checks = doctor.check_service(str(bad))
    assert [(c.name, c.status, c.blocking) for c in checks] == [("service config", ERROR, True)]


def test_a_working_service_is_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fakeredis = pytest.importorskip("fakeredis")
    monkeypatch.setattr("zues_scan.server.queue.connect", lambda config: fakeredis.FakeRedis())
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    config = tmp_path / "service.toml"
    config.write_text(
        f'[service]\ndb = "{tmp_path.as_posix()}/r.db"\n[[targets]]\nname = "lan"\n'
        f'target = "10.0.0.0/24"\nscope = "{tmp_path.as_posix()}/scope.txt"\n',
        encoding="utf-8",
    )
    checks = {c.name: c for c in doctor.check_service(str(config))}
    assert checks["service config"].detail.endswith("1 target(s)")
    assert checks["database"].status == INFO  # the first scan creates it
    assert checks["redis"].status == WARN and "has no password" in checks["redis"].detail

    (tmp_path / "redis.pass").write_text("s3cret\n", encoding="utf-8")
    text = config.read_text(encoding="utf-8").replace(
        "[service]\n", f'[service]\nredis_password_file = "{tmp_path.as_posix()}/redis.pass"\n'
    )
    config.write_text(text, encoding="utf-8")
    checks = {c.name: c for c in doctor.check_service(str(config))}
    assert checks["redis"].status == OK and checks["redis"].detail.endswith("(password)")


def test_the_database_should_use_write_ahead_logging(tmp_path: Path) -> None:
    import sqlite3
    from contextlib import closing

    from zues_scan.storage import Storage

    config = tmp_path / "service.toml"
    config.write_text(f'[service]\ndb = "{tmp_path.as_posix()}/r.db"\n', encoding="utf-8")
    with Storage(tmp_path / "r.db"):
        pass
    checks = {c.name: c for c in doctor.check_service(str(config))}
    assert checks["database"].status == OK and "write-ahead" in checks["database"].detail

    with closing(sqlite3.connect(tmp_path / "r.db")) as conn:
        conn.execute("PRAGMA journal_mode = DELETE")  # e.g. a backup copied in by hand
    checks = {c.name: c for c in doctor.check_service(str(config))}
    hint = checks["database"].hint or ""
    assert checks["database"].status == WARN and "start a service" in hint


def test_doctor_checks_the_service_the_environment_describes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """In the image / compose there is no --config: ZUES_DB says there is a service."""
    from zues_scan import cli

    monkeypatch.delenv("ZUES_CONFIG", raising=False)
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "zues.db"))
    monkeypatch.setenv("ZUES_REDIS_URL", "redis://127.0.0.1:1/0")  # nothing listens there

    cli.main(["doctor", "--json"])

    names = {c["name"] for c in json.loads(capsys.readouterr().out)["checks"]}
    assert {"service config", "database"} <= names


def test_dns_resolvers_are_shown_or_their_absence_warned() -> None:
    shown = check_dns_resolvers(["10.0.0.53", "8.8.8.8"])
    assert (shown.status, shown.detail) == (OK, "10.0.0.53, 8.8.8.8 (the system's)")
    missing = check_dns_resolvers([])
    assert missing.status == WARN and "internal names not found" in missing.detail
