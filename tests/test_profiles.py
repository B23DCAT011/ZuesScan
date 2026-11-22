"""Tests for scan profiles and the config file (G6, G7)."""

from pathlib import Path

import pytest

from reconkit.profiles import (
    BUILTIN,
    DEFAULT_PROFILE,
    ProfileError,
    ScanProfile,
    check_ports,
    load_profiles,
    override,
)


def test_default_profile_keeps_the_previous_behaviour() -> None:
    assert DEFAULT_PROFILE == "standard"
    assert BUILTIN["standard"].nmap_args() == ["-sV", "-T4"]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("quick", ["-sV", "--version-intensity", "2", "-T4", "--top-ports", "100"]),
        (
            "full",
            [
                "-sV",
                "-T4",
                "-p",
                "-",
                "--max-retries",
                "3",
                "--host-timeout",
                "3600s",
                "--traceroute",
            ],
        ),
        ("gentle", ["-sV", "-T2", "--max-rate", "50", "--max-retries", "2"]),
    ],
)
def test_builtin_profiles(name: str, args: list[str]) -> None:
    assert BUILTIN[name].nmap_args() == args


def test_summary_is_readable() -> None:
    assert BUILTIN["full"].summary() == "all 65535 ports, -T4, traceroute, timeout 4h"
    assert BUILTIN["standard"].summary() == "top 1000 ports, -T4, timeout 15min"
    assert BUILTIN["gentle"].summary() == "top 1000 ports, -T2, max 50 pkt/s, timeout 1h"


@pytest.mark.parametrize("spec", ["22", "22,80,443", "1-65535", "8000-8100,22", "-"])
def test_valid_port_lists(spec: str) -> None:
    assert check_ports(spec) == spec


@pytest.mark.parametrize(
    "spec",
    ["", "0", "70000", "80-22", "22,", "22 80", "-oN out.txt", "22;id", "U:53", "T:22", "http"],
)
def test_invalid_port_lists_are_refused(spec: str) -> None:
    # Anything nmap could read as another option, or misread, stops the scan.
    with pytest.raises(ProfileError):
        check_ports(spec)


@pytest.mark.parametrize(
    "settings",
    [
        {"timing": 6},
        {"timing": -1},
        {"top_ports": 0},
        {"max_rate": 0},
        {"timeout": 0},
        {"version_intensity": 10},
        {"ports": "22", "top_ports": 100},
        {"version_detection": False, "version_intensity": 3},
    ],
)
def test_out_of_range_settings_are_refused(settings: dict[str, object]) -> None:
    with pytest.raises(ProfileError):
        ScanProfile(name="x", **settings)  # type: ignore[arg-type]


def test_profile_names_are_restricted() -> None:
    with pytest.raises(ProfileError, match="invalid profile name"):
        ScanProfile(name="Night Scan")


def test_override_changes_single_settings_and_skips_none() -> None:
    profile = override(BUILTIN["standard"], {"timing": 3, "max_rate": None})
    assert (profile.timing, profile.max_rate, profile.name) == (3, None, "standard")


def test_override_can_switch_between_port_list_and_top_ports() -> None:
    assert override(BUILTIN["quick"], {"ports": "22,80"}).top_ports is None
    assert override(BUILTIN["full"], {"top_ports": 200}).ports is None


def test_turning_version_detection_off_drops_the_intensity() -> None:
    profile = override(BUILTIN["quick"], {"version_detection": False})
    assert "-sV" not in profile.nmap_args()
    assert profile.version_intensity is None


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"colour": "red"}, "unknown setting"),
        ({"timing": "4"}, "must be a int"),
        ({"timing": True}, "must be a int"),
        ({"traceroute": "yes"}, "must be a bool"),
    ],
)
def test_override_checks_names_and_types(settings: dict[str, object], message: str) -> None:
    with pytest.raises(ProfileError, match=message):
        override(BUILTIN["standard"], settings)


def test_settings_are_recorded_without_the_description() -> None:
    settings = BUILTIN["full"].settings()
    assert settings["ports"] == "-"
    assert settings["name"] == "full"
    assert "description" not in settings


# --- config file ----------------------------------------------------------------------


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "reconkit.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_defines_profiles_on_top_of_a_builtin(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        """
        [profiles.nightly]
        base = "full"
        description = "every night at 2am"
        timing = 3
        max_rate = 300

        [profiles.web]
        ports = "80,443,8000-8100"
        """,
    )
    profiles = load_profiles(config)
    assert list(profiles)[:4] == ["quick", "standard", "full", "gentle"]
    nightly = profiles["nightly"]
    assert (nightly.ports, nightly.traceroute, nightly.timing, nightly.max_rate) == (
        "-",
        True,
        3,
        300,
    )
    web = profiles["web"]
    assert (web.ports, web.timing) == ("80,443,8000-8100", 4)  # base: standard


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[profiles.full]\ntiming = 3\n", "redefine a built-in"),
        ('[profiles.x]\nbase = "turbo"\n', "base must be one of"),
        ("[profiles.x]\ntiming = 9\n", r"\[profiles.x\].*timing"),
        ('[profiles.x]\nports = "-oN /tmp/x"\n', "invalid port list"),
        ("[profiles.x]\nspeed = 3\n", "unknown setting 'speed'"),
        ("[scan]\ndb = 'x'\n", "unknown section"),
        ("profiles = 3\n", "must be a table"),
        ("[profiles\n", "cannot read config"),
    ],
)
def test_bad_config_is_refused_with_a_clear_message(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(ProfileError, match=message):
        load_profiles(_config(tmp_path, text))


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="config file not found"):
        load_profiles(tmp_path / "nope.toml")
