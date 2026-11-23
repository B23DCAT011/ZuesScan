"""Tests for the nmap plugin — no binary required.

Parsing is tested on a saved XML sample; `scan()` is tested by replacing
`subprocess.run`, so each failure mode can be triggered on demand.
"""

import errno
import shutil
import subprocess
from pathlib import Path

import pytest

from zues_scan.plugins.base import ScanError, ScannerPlugin
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.profiles import BUILTIN, override
from zues_scan.schema import ScanTarget

DATA = Path(__file__).parent / "data"
SAMPLE = (DATA / "nmap_sample.xml").read_text(encoding="utf-8")
TWO_HOSTS = (DATA / "nmap_two_hosts.xml").read_text(encoding="utf-8")

# What the scope guard hands a plugin when the user asks for "scanme.lab".
LAB = ScanTarget(requested="scanme.lab", addresses=("10.0.0.5",), hostname="scanme.lab")


def _plugin(**settings: object) -> NmapPlugin:
    """The plugin with the standard profile, some settings changed."""
    return NmapPlugin(override(BUILTIN["standard"], settings))


def _ip_target(address: str) -> ScanTarget:
    return ScanTarget(requested=address, addresses=(address,))


def test_satisfies_plugin_protocol() -> None:
    assert isinstance(NmapPlugin(), ScannerPlugin)


# --- command line: nmap is given addresses, never a name (G4) --------------------


def test_builds_argument_list_without_shell() -> None:
    cmd = NmapPlugin()._command(LAB)
    assert cmd[0] == "nmap"
    assert "-oX" in cmd and "-" in cmd


def test_command_scans_the_resolved_address_not_the_name() -> None:
    cmd = NmapPlugin()._command(LAB)
    assert cmd[-1] == "10.0.0.5"
    assert "scanme.lab" not in cmd  # nmap must not resolve the name a second time


def test_command_scans_every_address_of_a_name() -> None:
    target = ScanTarget(
        requested="scanme.lab", addresses=("10.0.0.5", "10.0.0.6"), hostname="scanme.lab"
    )
    assert NmapPlugin()._command(target)[-2:] == ["10.0.0.5", "10.0.0.6"]


def test_command_excludes_denied_addresses() -> None:
    target = ScanTarget(
        requested="10.0.0.0/24", addresses=("10.0.0.0/24",), exclude=("10.0.0.1", "10.0.0.64/26")
    )
    cmd = NmapPlugin()._command(target)
    at = cmd.index("--exclude")
    assert cmd[at + 1] == "10.0.0.1,10.0.0.64/26"
    assert cmd[-1] == "10.0.0.0/24"


def test_command_has_no_exclude_flag_when_nothing_is_denied() -> None:
    assert "--exclude" not in NmapPlugin()._command(LAB)


# --- parsing: one asset per host (G1, G16) ---------------------------------------


def test_host_scanned_by_name_is_named_after_the_request() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE, hostname="scanme.lab")
    assert asset.host == "scanme.lab"  # the name the user asked for, not the PTR name
    assert asset.ip == "10.0.0.5"


def test_host_scanned_by_address_is_named_after_its_ip() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE)
    assert (asset.host, asset.ip) == ("10.0.0.5", "10.0.0.5")  # not the PTR name


def test_parses_only_open_ports() -> None:
    (asset,) = NmapPlugin.parse_xml(SAMPLE)
    ports = {s.port for s in asset.services}
    assert ports == {22, 80}  # 443 is closed and excluded


def test_range_scan_yields_one_asset_per_live_host() -> None:
    # Every service stays attached to the machine it was found on.
    web, quiet = NmapPlugin.parse_xml(TWO_HOSTS)  # 10.0.0.9 is down: not an asset
    assert (web.host, web.ip) == ("10.0.0.5", "10.0.0.5")  # IP, not MAC or PTR name
    assert [s.port for s in web.services] == [22]
    assert (quiet.host, quiet.ip) == ("10.0.0.7", "10.0.0.7")
    assert quiet.services == []  # up, nothing open: still reported


def test_ipv6_address_is_used_as_the_ip() -> None:
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="2001:db8::5" addrtype="ipv6"/></host></nmaprun>'
    )
    (asset,) = NmapPlugin.parse_xml(xml)
    assert (asset.host, asset.ip) == ("2001:db8::5", "2001:db8::5")


def test_extracts_service_fields() -> None:
    services = {s.port: s for s in NmapPlugin.parse_xml(SAMPLE)[0].services}
    ssh = services[22]
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "7.4"
    assert ssh.cpe == "cpe:/a:openbsd:openssh:7.4"
    assert ssh.protocol == "tcp"


def test_empty_output_yields_no_assets() -> None:
    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    assert NmapPlugin.parse_xml(xml) == []


# --- scan(): every way nmap can fail must surface as ScanError (G3) ---------------


def _fake_run(monkeypatch: pytest.MonkeyPatch, outcome: object) -> None:
    """Make scan() see nmap as installed, and `subprocess.run` raise/return `outcome`."""

    def run(*args: object, **kwargs: object) -> object:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", run)


def test_scan_returns_assets_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=SAMPLE, stderr="")
    _fake_run(monkeypatch, done)
    (asset,) = NmapPlugin().scan(LAB).assets
    assert (asset.host, asset.ip) == ("scanme.lab", "10.0.0.5")
    assert {s.port for s in asset.services} == {22, 80}


def test_scan_wraps_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    # Nor in the place the Windows installer uses (found even when PATH is stale).
    monkeypatch.setattr("zues_scan.tools._windows_install", lambda _name: None)
    with pytest.raises(ScanError, match="not installed"):
        NmapPlugin().scan(LAB)


def test_scan_wraps_nonzero_exit_and_keeps_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = subprocess.CalledProcessError(
        returncode=1, cmd=["nmap"], stderr="You requested a scan type which requires root\n"
    )
    _fake_run(monkeypatch, failure)
    with pytest.raises(ScanError, match="exited with code 1 scanning scanme.lab") as excinfo:
        NmapPlugin().scan(LAB)
    assert excinfo.value.plugin == "nmap"
    assert excinfo.value.stderr == "You requested a scan type which requires root"


def test_a_refused_raw_socket_says_how_to_allow_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # In a container without NET_RAW (or with no-new-privileges), nmap's raw socket is
    # refused and it only prints "QUITTING!": the error must say what to change.
    failure = subprocess.CalledProcessError(
        returncode=1, cmd=["nmap"], stderr="dnet: Failed to open device eth0\nQUITTING!\n"
    )
    _fake_run(monkeypatch, failure)
    with pytest.raises(ScanError, match="--cap-add NET_RAW and no-new-privileges off"):
        NmapPlugin().scan(LAB)


def test_a_binary_the_process_may_not_execute_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap carries a file capability the container's bounding set lacks: exec gives EPERM.
    _fake_run(monkeypatch, PermissionError(errno.EPERM, "Operation not permitted", "nmap"))
    with pytest.raises(ScanError, match="could not start nmap: .*CAP_NET_RAW"):
        NmapPlugin().scan(LAB)


def test_scan_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, subprocess.TimeoutExpired(cmd=["nmap"], timeout=5))
    with pytest.raises(ScanError, match="timed out after 5s"):
        _plugin(timeout=5).scan(LAB)


def test_scan_wraps_failure_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, PermissionError("access denied"))
    with pytest.raises(ScanError, match="could not start nmap"):
        NmapPlugin().scan(LAB)


def test_scan_wraps_truncated_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=SAMPLE[: len(SAMPLE) // 2], stderr=""
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="unreadable XML"):
        NmapPlugin().scan(LAB)


# --- scan(): nmap exits 0 but examined nothing (G2) --------------------------------


def _run_xml(up: int, down: int, total: int) -> str:
    """Minimal nmap output carrying only its own host counts."""
    return (
        '<?xml version="1.0"?><nmaprun><runstats>'
        f'<hosts up="{up}" down="{down}" total="{total}"/>'
        "</runstats></nmaprun>"
    )


def test_scan_rejects_zero_hosts_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap exits 0 with total="0" when it ends up with nothing to scan.
    done = subprocess.CompletedProcess(
        args=["nmap"],
        returncode=0,
        stdout=_run_xml(up=0, down=0, total=0),
        stderr="WARNING: No targets were specified, so 0 hosts scanned.\n",
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="scanned 0 hosts") as excinfo:
        NmapPlugin().scan(_ip_target("10.0.0.5"))
    assert excinfo.value.stderr == "WARNING: No targets were specified, so 0 hosts scanned."


def test_scan_rejects_no_host_up(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=_run_xml(up=0, down=1, total=1), stderr=""
    )
    _fake_run(monkeypatch, done)
    with pytest.raises(ScanError, match="no host responded"):
        NmapPlugin().scan(_ip_target("192.0.2.1"))


def test_scan_accepts_live_host_with_no_open_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host that answered and has nothing open is a real, clean result.
    xml = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
        '<runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )
    done = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=xml, stderr="")
    _fake_run(monkeypatch, done)
    (asset,) = NmapPlugin().scan(_ip_target("10.0.0.5")).assets
    assert asset.ip == "10.0.0.5"
    assert asset.services == []


# --- version(): recorded with every run (G14) --------------------------------------


def test_version_is_read_from_nmap_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    banner = "Nmap version 7.92 ( https://nmap.org )\nPlatform: i686-pc-windows-windows\n"
    _fake_run(monkeypatch, subprocess.CompletedProcess(["nmap"], 0, stdout=banner, stderr=""))
    assert NmapPlugin().version() == "7.92"


@pytest.mark.parametrize(
    "outcome",
    [
        FileNotFoundError("nmap"),
        subprocess.TimeoutExpired(cmd="nmap", timeout=10),
        subprocess.CalledProcessError(returncode=1, cmd="nmap"),
        subprocess.CompletedProcess(["nmap"], 0, stdout="something unexpected", stderr=""),
    ],
)
def test_unknown_version_is_none_never_an_error(
    monkeypatch: pytest.MonkeyPatch, outcome: object
) -> None:
    _fake_run(monkeypatch, outcome)
    assert NmapPlugin().version() is None


# --- evidence: nmap's own output is handed back untouched (G13) ------------------


def test_scan_returns_the_raw_xml_and_the_exact_command(monkeypatch: pytest.MonkeyPatch) -> None:
    done = subprocess.CompletedProcess(["nmap"], 0, stdout=SAMPLE, stderr="Warning: slow\n")
    _fake_run(monkeypatch, done)
    result = NmapPlugin().scan(LAB)

    (raw,) = result.raw
    assert raw.plugin == "nmap"
    assert raw.format == "nmap-xml"
    assert raw.content == SAMPLE  # byte for byte what nmap printed
    assert raw.command == tuple(NmapPlugin()._command(LAB))
    assert raw.stderr == "Warning: slow"
    # The assets are a reading of that same output.
    assert [a.ip for a in NmapPlugin.parse_xml(raw.content, hostname="scanme.lab")] == [
        a.ip for a in result.assets
    ]


def test_failed_scan_still_hands_back_what_nmap_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    # "No host responded" is our conclusion; the XML it was drawn from is kept so
    # that the conclusion can be checked.
    xml = '<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
    _fake_run(monkeypatch, subprocess.CompletedProcess(["nmap"], 0, stdout=xml, stderr=""))
    with pytest.raises(ScanError) as caught:
        NmapPlugin().scan(_ip_target("192.0.2.1"))
    assert caught.value.output is not None
    assert caught.value.output.content == xml


def test_unreadable_output_is_kept_as_it_is(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(
        monkeypatch, subprocess.CompletedProcess(["nmap"], 0, stdout="<nmaprun><host>", stderr="")
    )
    with pytest.raises(ScanError) as caught:
        NmapPlugin().scan(LAB)
    assert caught.value.output is not None
    assert caught.value.output.content == "<nmaprun><host>"


def test_timed_out_scan_keeps_what_nmap_printed_so_far(monkeypatch: pytest.MonkeyPatch) -> None:
    timeout = subprocess.TimeoutExpired(
        cmd="nmap", timeout=5, output=b"<nmaprun><host>", stderr=b"Stats: 0:00:05 elapsed\n"
    )
    _fake_run(monkeypatch, timeout)
    with pytest.raises(ScanError, match="timed out") as caught:
        _plugin(timeout=5).scan(LAB)
    assert caught.value.output is not None
    assert caught.value.output.content == "<nmaprun><host>"
    assert caught.value.stderr == "Stats: 0:00:05 elapsed"


def test_scan_that_never_ran_has_no_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, subprocess.TimeoutExpired(cmd="nmap", timeout=5))
    with pytest.raises(ScanError) as caught:
        _plugin(timeout=5).scan(LAB)
    assert caught.value.output is None


# --- traceroute: the path to each host, for the map (M1) ---------------------------

TRACE = (DATA / "nmap_traceroute.xml").read_text(encoding="utf-8")


def test_traceroute_is_off_by_default() -> None:
    assert "--traceroute" not in NmapPlugin()._command(LAB)


def test_traceroute_adds_the_flag_and_still_scans_only_the_addresses() -> None:
    cmd = _plugin(traceroute=True)._command(LAB)
    assert "--traceroute" in cmd
    assert cmd[-1] == "10.0.0.5"  # the target list is unchanged


def test_route_is_read_hop_by_hop() -> None:
    web, _, _ = NmapPlugin.parse_xml(TRACE)
    assert [(h.ttl, h.ip, h.rtt_ms, h.name) for h in web.route] == [
        (1, "192.168.1.1", 0.52, "gateway.lan"),
        (3, "10.0.0.1", 3.10, None),  # hop 2 never answered: a gap, not invented
        (4, "10.0.0.5", 3.40, None),  # the last hop is the host itself
    ]


def test_hop_not_timed_for_this_host_has_no_rtt() -> None:
    _, other, _ = NmapPlugin.parse_xml(TRACE)
    assert [h.rtt_ms for h in other.route] == [None, None, 3.90]  # rtt="--"
    assert [h.ip for h in other.route] == ["192.168.1.1", "10.0.0.1", "10.0.0.7"]


def test_host_without_trace_has_an_empty_route() -> None:
    *_, untraced = NmapPlugin.parse_xml(TRACE)
    assert untraced.ip == "10.0.0.9"
    assert untraced.route == []
    (plain,) = NmapPlugin.parse_xml(SAMPLE)
    assert plain.route == []


def test_unreadable_hops_are_skipped_and_the_rest_ordered() -> None:
    xml = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<trace><hop ttl="2" ipaddr="10.0.0.1" rtt="nan"/><hop ttl="x" ipaddr="1.1.1.1"/>'
        '<hop ttl="0" ipaddr="1.1.1.2"/><hop ttl="1"/></trace></host></nmaprun>'
    )
    (asset,) = NmapPlugin.parse_xml(xml)
    assert [(h.ttl, h.ip, h.rtt_ms) for h in asset.route] == [
        (1, None, None),
        (2, "10.0.0.1", None),
    ]


def test_scan_returns_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_run(monkeypatch, subprocess.CompletedProcess(["nmap"], 0, stdout=TRACE, stderr=""))
    target = ScanTarget(requested="10.0.0.0/24", addresses=("10.0.0.0/24",))
    assets = _plugin(traceroute=True).scan(target).assets
    assert [len(a.route) for a in assets] == [3, 3, 0]


# --- scan profiles (G6, G7) -----------------------------------------------------------


def test_profile_decides_the_command_line() -> None:
    cmd = NmapPlugin(BUILTIN["full"])._command(LAB)
    assert cmd == [
        "nmap", "-sV", "-T4", "-p", "-", "--max-retries", "3", "--host-timeout", "3600s",
        "--traceroute", "-oX", "-", "10.0.0.5",
    ]  # fmt: skip
    assert NmapPlugin()._command(LAB) == ["nmap", "-sV", "-T4", "-oX", "-", "10.0.0.5"]


def test_profile_timeout_applies_to_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def run(*args: object, **kwargs: object) -> object:
        seen.update(kwargs)
        return subprocess.CompletedProcess(["nmap"], 0, stdout=SAMPLE, stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", run)
    NmapPlugin(BUILTIN["full"]).scan(LAB)
    assert seen["timeout"] == 4 * 3600


# --- IPv6: one nmap run per address family (G22) ----------------------------------------------

V6_UP = (
    '<nmaprun><host><status state="up"/><address addr="2001:db8::5" addrtype="ipv6"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>'
    '</port></ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
)
V6_DOWN = '<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
DUAL = ScanTarget(
    requested="scanme.lab",
    addresses=("10.0.0.5", "2001:db8::5"),
    exclude=("2001:db8::1",),
    hostname="scanme.lab",
)


def _per_family(monkeypatch: pytest.MonkeyPatch, v4: str, v6: str) -> list[list[str]]:
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> object:
        commands.append(command)
        out = v6 if "-6" in command else v4
        return subprocess.CompletedProcess(command, 0, stdout=out, stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(subprocess, "run", run)
    return commands


def test_dual_stack_target_is_scanned_once_per_family(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = _per_family(monkeypatch, SAMPLE, V6_UP)
    result = NmapPlugin().scan(DUAL)
    v4, v6 = commands
    assert "-6" not in v4 and v4[-1] == "10.0.0.5" and "--exclude" not in v4
    assert v6[:2] == ["nmap", "-6"] and v6[-1] == "2001:db8::5"
    assert v6[v6.index("--exclude") + 1] == "2001:db8::1"  # excludes go with their family
    assert [a.ip for a in result.assets] == ["10.0.0.5", "2001:db8::5"]
    assert all(a.host == "scanme.lab" for a in result.assets)
    assert len(result.raw) == 2 and result.notes == []


def test_unreachable_ipv6_is_a_note_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _per_family(monkeypatch, SAMPLE, V6_DOWN)
    result = NmapPlugin().scan(DUAL)
    assert [a.ip for a in result.assets] == ["10.0.0.5"]
    (note,) = result.notes
    assert "no host responded for scanme.lab over IPv6" in note
    assert result.raw[-1].content == V6_DOWN  # the proof is kept


def test_no_family_answering_is_still_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    down = '<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
    _per_family(monkeypatch, down, V6_DOWN)
    with pytest.raises(ScanError, match="no host responded for scanme.lab"):
        NmapPlugin().scan(DUAL)


def test_ipv6_only_target_uses_dash_6(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = _per_family(monkeypatch, SAMPLE, V6_UP)
    target = ScanTarget(requested="2001:db8::/120", addresses=("2001:db8::/120",))
    (asset,) = NmapPlugin().scan(target).assets
    assert asset.ip == "2001:db8::5"
    assert commands[0][1] == "-6"
