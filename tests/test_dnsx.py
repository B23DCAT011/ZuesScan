"""The dnsx discovery plugin: wordlist, resolvers, wildcard DNS, partial runs."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from zues_scan.plugins import dnsx as dnsx_plugin
from zues_scan.plugins import registry as plugin_registry
from zues_scan.plugins.base import ScanError
from zues_scan.plugins.dnsx import (
    BUNDLED,
    PROBE,
    DnsxPlugin,
    parse_jsonl,
    parse_resolv_conf,
    parse_wordlist,
)
from zues_scan.profiles import BUILTIN
from zues_scan.scope import Activity


def line(host: str, *a: str, aaaa: tuple[str, ...] = ()) -> str:
    record: dict[str, Any] = {"host": host, "a": list(a)}
    if aaaa:
        record["aaaa"] = list(aaaa)
    return json.dumps(record)


def test_the_wordlist_is_cleaned() -> None:
    text = "# comment\n\nWWW\nvpn\nwww\n bad word \n-dash\napi.dev\n.mail.\n" + "x" * 64 + "\n"
    assert parse_wordlist(text) == ["www", "vpn", "api.dev", "mail"]


def test_the_bundled_wordlist_is_usable() -> None:
    words = parse_wordlist(BUNDLED.read_text(encoding="utf-8"))
    assert 300 < len(words) < 2000  # seconds, not hours
    assert {"www", "vpn", "intranet", "gitlab", "staging"} <= set(words)


def test_system_resolvers_ipv4_only() -> None:
    text = "# generated\nnameserver 127.0.0.11\nnameserver ::1\nnameserver bogus\nsearch lab\n"
    assert parse_resolv_conf(text + "nameserver 10.0.0.53\n") == ["127.0.0.11", "10.0.0.53"]


def test_names_outside_the_domain_or_unreadable_are_skipped() -> None:
    text = "\n".join(
        [
            line("vpn.example.com", "10.0.0.1"),
            line("VPN.example.com.", "10.0.0.2"),  # same name: one entry, both addresses
            line("example.com.evil.net", "6.6.6.6"),
            line("ipv6.example.com", aaaa=("2001:db8::1",)),
            "not json",
            json.dumps({"no": "host"}),
        ]
    )
    names, wildcard, skipped = parse_jsonl(text, "example.com")
    assert (names, wildcard, skipped) == (["ipv6.example.com", "vpn.example.com"], 0, 3)


def test_wildcard_answers_are_dropped_real_names_kept() -> None:
    text = "\n".join(
        [
            line(f"{PROBE}a1b2.example.com", "1.2.3.4"),
            line(f"{PROBE}c3d4.example.com", "1.2.3.5"),
            line("www.example.com", "1.2.3.4"),  # only the wildcard's address
            line("ftp.example.com", "1.2.3.5", "1.2.3.4"),
            line("vpn.example.com", "10.9.9.9"),  # a real record of its own
        ]
    )
    assert parse_jsonl(text, "example.com") == (["vpn.example.com"], 2, 0)


@pytest.fixture
def fake_dnsx(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """`subprocess.run` answering like dnsx: every name in the input file but `nope.` resolves."""
    calls: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        names = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        calls.append({"command": command, "names": names, "env": kwargs["env"]})
        out = [line(n, "10.0.0.7") for n in names if not n.startswith(("nope.", PROBE))]
        return subprocess.CompletedProcess(command, 0, stdout="\n".join(out), stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dnsx")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_discover_tries_every_word_and_two_random_names(
    fake_dnsx: list[dict[str, Any]], tmp_path: Path
) -> None:
    words = tmp_path / "words.txt"
    words.write_text("vpn\nnope\nintranet\n", encoding="utf-8")
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.0.0.53\n", encoding="utf-8")
    plugin = DnsxPlugin(wordlist=str(words), rate=20, resolv_conf=str(resolv), recurse=0)
    result = plugin.discover("Example.com.")
    assert result.names == ["intranet.example.com", "vpn.example.com"]
    (call,) = fake_dnsx
    asked = call["names"]
    assert asked[:3] == ["vpn.example.com", "nope.example.com", "intranet.example.com"]
    assert len([n for n in asked if n.startswith(PROBE)]) == 2
    command = call["command"]
    assert command[command.index("-rl") + 1] == "20"
    assert command[command.index("-r") + 1] == "10.0.0.53"
    assert call["env"]["HOME"] != str(Path.home())  # its config goes to a throwaway home
    assert result.raw[0].format == "dnsx-jsonl"
    assert result.notes[0] == f"tried 3 name(s) from {words}; 2 found"


def test_without_a_resolv_conf_dnsx_picks_its_own(
    fake_dnsx: list[dict[str, Any]], tmp_path: Path
) -> None:
    DnsxPlugin(resolv_conf=str(tmp_path / "absent")).discover("example.com")
    assert "-r" not in fake_dnsx[0]["command"]
    assert len(fake_dnsx[0]["names"]) > 300  # the bundled list


def test_out_of_time_keeps_what_was_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(
            command, 5, output=line("vpn.example.com", "10.0.0.7").encode()
        )

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dnsx")
    monkeypatch.setattr(subprocess, "run", run)
    result = DnsxPlugin(timeout=5).discover("example.com")
    assert result.names == ["vpn.example.com"]
    assert any(n.startswith("stopped after 5s") for n in result.notes)


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (subprocess.CalledProcessError(1, "dnsx", stderr="bad flag"), "exited with code 1"),
        (OSError("exec format error"), "could not start dnsx"),
    ],
)
def test_failures_are_scan_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    def run(command: list[str], **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dnsx")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ScanError, match=message):
        DnsxPlugin().discover("example.com")


def test_an_unreadable_or_empty_wordlist_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dnsx")
    with pytest.raises(ScanError, match="cannot read the DNS wordlist"):
        DnsxPlugin(wordlist=str(tmp_path / "absent.txt")).discover("example.com")
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n", encoding="utf-8")
    with pytest.raises(ScanError, match="holds no usable word"):
        DnsxPlugin(wordlist=str(empty)).discover("example.com")


def test_registered_as_a_scan_level_discoverer_with_the_profiles_rate() -> None:
    spec = plugin_registry.load(lambda: []).get("dnsx", "discovery")
    assert spec.activity is Activity.SCAN  # it asks the domain's own DNS servers
    profile = BUILTIN["full"]
    ctx = plugin_registry.PluginContext(profile=profile, dns_wordlist="w.txt")
    (built,) = plugin_registry.load(lambda: []).build(["dnsx"], "discovery", ctx)
    assert (built.wordlist, built.rate) == ("w.txt", profile.check_rate or 100)


def test_on_windows_the_dns_servers_of_windows(
    fake_dnsx: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    found = ["10.1.0.53", "fec0:0:0:ffff::1", "10.1.0.53", "not an address", "10.2.0.53"]
    monkeypatch.setattr(dnsx_plugin, "_network_params_dns", lambda: found)
    result = DnsxPlugin().discover("example.com")
    command = fake_dnsx[0]["command"]
    assert command[command.index("-r") + 1] == "10.1.0.53,10.2.0.53"  # IPv4, each once
    assert not any("public resolvers" in n for n in result.notes)


def test_without_a_system_resolver_the_run_says_so(
    fake_dnsx: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(dnsx_plugin, "_network_params_dns", lambda: [])
    result = DnsxPlugin().discover("example.com")
    assert "-r" not in fake_dnsx[0]["command"]
    assert any("dnsx asked public resolvers" in n for n in result.notes)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows' own API")
def test_windows_names_its_dns_servers() -> None:
    # Any Windows machine with a network has at least one; each is an IPv4 address.
    servers = dnsx_plugin.windows_resolvers()
    assert servers and all(
        isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address) for s in servers
    )


def zone(monkeypatch: pytest.MonkeyPatch, records: dict[str, str]) -> list[list[str]]:
    """`subprocess.run` answering like dnsx over a zone: only `records` resolve (a key
    `*.x` answers for every name under x)."""
    asked: list[list[str]] = []

    def address(name: str) -> str | None:
        if name in records:
            return records[name]
        parent = name.split(".", 1)[1]
        return records.get(f"*.{parent}")

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        names = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        asked.append(names)
        out = [line(n, a) for n in names if (a := address(n)) is not None]
        return subprocess.CompletedProcess(command, 0, stdout="\n".join(out), stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dnsx")
    monkeypatch.setattr(subprocess, "run", run)
    return asked


def test_one_level_deeper_under_what_was_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    words = tmp_path / "words.txt"
    words.write_text("dev\napi\nwild\ndb\n", encoding="utf-8")
    asked = zone(
        monkeypatch,
        {
            "dev.example.com": "10.0.0.1",
            "api.dev.example.com": "10.0.0.2",  # only found one level deeper
            "db.api.dev.example.com": "10.0.0.3",  # two levels: not looked for
            "wild.example.com": "10.0.0.9",
            "*.wild.example.com": "10.0.0.9",  # a wildcard one level down
        },
    )
    result = DnsxPlugin(wordlist=str(words), resolv_conf=str(tmp_path / "none")).discover(
        "example.com"
    )
    assert result.names == ["api.dev.example.com", "dev.example.com", "wild.example.com"]
    first, second = asked
    assert {n.split(".", 1)[1] for n in second} == {"dev.example.com", "wild.example.com"}
    assert len([n for n in second if n.startswith(PROBE)]) == 4  # two under each
    assert len(result.raw) == 2
    assert "one level deeper under 2 name(s) (dev.example.com, wild.example.com): 1 more found" in (
        result.notes
    )
    assert any(n.startswith("wildcard DNS under wild.example.com: 4 name(s)") for n in result.notes)


def test_the_deeper_pass_can_be_turned_off_and_is_capped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    words = tmp_path / "words.txt"
    words.write_text("\n".join(f"w{i}" for i in range(15)) + "\n", encoding="utf-8")
    asked = zone(monkeypatch, {f"w{i}.example.com": "10.0.0.1" for i in range(15)})
    DnsxPlugin(wordlist=str(words), recurse=0).discover("example.com")
    assert len(asked) == 1
    asked.clear()
    DnsxPlugin(wordlist=str(words)).discover("example.com")
    parents = {n.split(".", 1)[1] for n in asked[1]}
    assert len(parents) == dnsx_plugin.RECURSE == 10
