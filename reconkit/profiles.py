"""Scan profiles — how hard, how wide and how fast to scan (G6, G7).

A profile is a named set of scanner settings. Four are built in:

    quick     the 100 most common ports, fast; a first look
    standard  nmap's 1,000 most common ports (the default)
    full      all 65,535 TCP ports + traceroute; what a scheduled scan should use
    gentle    standard ports, slowed down and rate-limited; for fragile or busy networks

A TOML config file (`--config`) can define more, each starting from a built-in one, and
command-line flags override single settings for one scan. Precedence, lowest first:

    built-in profile  <  [profiles.<name>] in the config file  <  command-line flags

Every setting is checked here, before anything runs: a port list or a number that
nmap would misread must stop the scan, not be passed on and guessed at.

Example config:

    [profiles.nightly]
    base = "full"          # start from a built-in profile
    timing = 3
    max_rate = 300         # packets per second, at most
    host_timeout = 1800    # give up on one host after 30 minutes
    timeout = 14400        # give up on the whole scan after 4 hours
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any


class ProfileError(Exception):
    """A profile or config file is invalid: the scan must not start."""


# "22", "1-1024", "22,80,443,8000-8100": TCP ports only. "-" alone means all ports.
_PORT_ITEM = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")


def check_ports(spec: str) -> str:
    """Validate a port list for nmap's `-p`; return it unchanged."""
    if spec == "-":
        return spec
    if not spec:
        raise ProfileError("empty port list")
    for item in spec.split(","):
        match = _PORT_ITEM.fullmatch(item)
        if match is None:
            raise ProfileError(
                f"invalid port list {spec!r}: use ports and ranges like 22,80,8000-8100 "
                "(TCP only), or '-' for all ports"
            )
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if not 1 <= low <= high <= 65535:
            raise ProfileError(f"invalid port range {item!r} in {spec!r}: ports are 1-65535")
    return spec


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """Settings for one scan. `None` means "nmap's own default"."""

    name: str
    description: str = ""
    # Which ports: an explicit list (`-p`), else the N most common (`--top-ports`),
    # else nmap's default (the 1,000 most common).
    ports: str | None = None
    top_ports: int | None = None
    timing: int = 4  # -T0 (paranoid) ... -T5 (insane); -T4 suits a healthy network
    version_detection: bool = True  # -sV: needed to match CVEs
    version_intensity: int | None = None  # 0 (light) ... 9 (all probes)
    traceroute: bool = False
    # Treat every address as up (-Pn): finds hosts that ignore ping, but a range scan
    # then probes every address, which is much slower.
    assume_up: bool = False
    max_rate: int | None = None  # packets per second, at most
    max_retries: int | None = None  # retransmissions per probe
    host_timeout: int | None = None  # seconds before nmap gives up on one host
    timeout: int = 900  # seconds before ReconKit stops the whole scan

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", self.name):
            raise ProfileError(
                f"invalid profile name {self.name!r}: lowercase letters, digits, - and _"
            )
        if self.ports is not None:
            check_ports(self.ports)
        if self.ports is not None and self.top_ports is not None:
            raise ProfileError(f"profile {self.name!r}: set either ports or top_ports, not both")
        _check_range(self.name, "top_ports", self.top_ports, 1, 65535)
        _check_range(self.name, "timing", self.timing, 0, 5)
        _check_range(self.name, "version_intensity", self.version_intensity, 0, 9)
        _check_range(self.name, "max_rate", self.max_rate, 1, 1_000_000)
        _check_range(self.name, "max_retries", self.max_retries, 0, 50)
        _check_range(self.name, "host_timeout", self.host_timeout, 1, 7 * 86400)
        _check_range(self.name, "timeout", self.timeout, 1, 7 * 86400)
        if self.version_intensity is not None and not self.version_detection:
            raise ProfileError(f"profile {self.name!r}: version_intensity needs version_detection")

    def nmap_args(self) -> list[str]:
        """The nmap options this profile stands for (targets and output not included)."""
        args: list[str] = []
        if self.version_detection:
            args.append("-sV")
            if self.version_intensity is not None:
                args += ["--version-intensity", str(self.version_intensity)]
        args.append(f"-T{self.timing}")
        if self.ports is not None:
            args += ["-p", self.ports]
        elif self.top_ports is not None:
            args += ["--top-ports", str(self.top_ports)]
        if self.assume_up:
            args.append("-Pn")
        if self.max_rate is not None:
            args += ["--max-rate", str(self.max_rate)]
        if self.max_retries is not None:
            args += ["--max-retries", str(self.max_retries)]
        if self.host_timeout is not None:
            args += ["--host-timeout", f"{self.host_timeout}s"]
        if self.traceroute:
            args.append("--traceroute")
        return args

    def settings(self) -> dict[str, Any]:
        """Every setting, for the record kept with a run."""
        return {k: v for k, v in asdict(self).items() if k != "description"}

    def summary(self) -> str:
        """One line for people, e.g. "all ports, -T4, traceroute, 4h timeout"."""
        if self.ports == "-":
            ports = "all 65535 ports"
        elif self.ports is not None:
            ports = f"ports {self.ports}"
        else:
            ports = f"top {self.top_ports or 1000} ports"
        parts = [ports, f"-T{self.timing}"]
        if not self.version_detection:
            parts.append("no version detection")
        if self.assume_up:
            parts.append("assume up (-Pn)")
        if self.max_rate is not None:
            parts.append(f"max {self.max_rate} pkt/s")
        if self.traceroute:
            parts.append("traceroute")
        parts.append(f"timeout {_duration(self.timeout)}")
        return ", ".join(parts)


def _check_range(profile: str, key: str, value: int | None, low: int, high: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ProfileError(f"profile {profile!r}: {key} must be a whole number {low}-{high}")


def _duration(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}min"
    return f"{seconds}s"


BUILTIN: dict[str, ScanProfile] = {
    p.name: p
    for p in (
        ScanProfile(
            name="quick",
            description="100 most common ports, fast: a first look",
            top_ports=100,
            version_intensity=2,
            timeout=300,
        ),
        ScanProfile(
            name="standard",
            description="nmap's 1,000 most common ports (default)",
            timeout=900,
        ),
        ScanProfile(
            name="full",
            description="all 65,535 TCP ports + traceroute: for scheduled scans",
            ports="-",
            traceroute=True,
            max_retries=3,
            host_timeout=3600,
            timeout=4 * 3600,
        ),
        ScanProfile(
            name="gentle",
            description="standard ports, slow and rate-limited: for fragile networks",
            timing=2,
            max_rate=50,
            max_retries=2,
            timeout=3600,
        ),
    )
}

DEFAULT_PROFILE = "standard"

# Settings a config file or a command-line flag may change.
_SETTINGS = {f.name: f for f in fields(ScanProfile) if f.name != "name"}
_TYPES: dict[str, tuple[type, ...]] = {
    "description": (str,),
    "ports": (str,),
    "top_ports": (int,),
    "timing": (int,),
    "version_detection": (bool,),
    "version_intensity": (int,),
    "traceroute": (bool,),
    "assume_up": (bool,),
    "max_rate": (int,),
    "max_retries": (int,),
    "host_timeout": (int,),
    "timeout": (int,),
}


def load_profiles(config: str | Path | None = None) -> dict[str, ScanProfile]:
    """The built-in profiles, plus those defined in `config` (a TOML file), if given."""
    profiles = dict(BUILTIN)
    if config is None:
        return profiles
    try:
        with Path(config).open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise ProfileError(f"config file not found: {config}") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"cannot read config file {config}: {exc}") from None

    unknown = set(data) - {"profiles"}
    if unknown:
        raise ProfileError(f"{config}: unknown section(s): {', '.join(sorted(unknown))}")
    defined = data.get("profiles", {})
    if not isinstance(defined, dict):
        raise ProfileError(f"{config}: [profiles] must be a table")
    for name, table in defined.items():
        if not isinstance(table, dict):
            raise ProfileError(f"{config}: [profiles.{name}] must be a table")
        if name in BUILTIN:
            raise ProfileError(
                f"{config}: [profiles.{name}] would redefine a built-in profile; "
                f'pick another name and use base = "{name}"'
            )
        settings = dict(table)
        base_name = settings.pop("base", DEFAULT_PROFILE)
        if base_name not in BUILTIN:
            raise ProfileError(
                f"{config}: [profiles.{name}] base must be one of {', '.join(BUILTIN)}"
            )
        try:
            profiles[name] = override(replace(BUILTIN[base_name], name=name), settings)
        except ProfileError as exc:
            raise ProfileError(f"{config}: [profiles.{name}]: {exc}") from None
    return profiles


def override(profile: ScanProfile, settings: dict[str, Any]) -> ScanProfile:
    """`profile` with some settings changed, each checked for name and type.

    A setting given as None is left as it is. Choosing a port list clears `top_ports`
    and the other way round, so an override can switch between the two.
    """
    changes: dict[str, Any] = {}
    for key, value in settings.items():
        if key not in _SETTINGS:
            raise ProfileError(f"unknown setting {key!r}")
        if value is None:
            continue
        types = _TYPES[key]
        if not isinstance(value, types) or (bool not in types and isinstance(value, bool)):
            raise ProfileError(f"setting {key!r} must be a {types[0].__name__}")
        changes[key] = value
    if "ports" in changes and "top_ports" not in changes:
        changes["top_ports"] = None
    if "top_ports" in changes and "ports" not in changes:
        changes["ports"] = None
    if changes.get("version_detection") is False and "version_intensity" not in changes:
        changes["version_intensity"] = None
    return replace(profile, **changes)
