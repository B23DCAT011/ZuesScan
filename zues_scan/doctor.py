"""`zues doctor` — what this machine can scan with, and how to fix what is missing.

Every external tool is checked the way ZuesScan will use it: found or not, which
version, and for nmap whether it may open raw sockets (without that, nmap silently
falls back to a slower TCP connect scan and cannot traceroute). For anything missing
or misconfigured, the exact command for *this* system is given — ZuesScan never
installs system packages itself: that needs administrator rights, and a security tool
must not take them on its own.

The checks are plain functions over injected facts (paths, platform, environment), so
that they are tested on any machine; `gather()` collects the real facts.
"""

from __future__ import annotations

import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zues_scan import __version__, tools

OK, WARN, MISSING, ERROR, INFO = "ok", "warn", "missing", "error", "info"
CAP_NET_RAW = 13  # bit number in a file's permitted capability set
CACHE_STALE_DAYS = 7


@dataclass
class Check:
    name: str
    status: str  # ok | warn | missing | error | info
    detail: str
    hint: str | None = None
    required: bool = False  # a problem here means: no scan is possible

    @property
    def blocking(self) -> bool:
        return self.required and self.status in (MISSING, ERROR)


@dataclass
class System:
    """The facts about this machine the checks depend on."""

    name: str  # platform.system(): Linux, Darwin, Windows
    distro: str = ""  # Linux: ID and ID_LIKE of /etc/os-release, e.g. "debian" or "ubuntu debian"
    pretty: str = ""
    euid: int | None = None
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def current(cls) -> System:
        name = platform.system()
        distro, pretty = "", ""
        if name == "Linux":
            release = _os_release()
            distro = " ".join(filter(None, (release.get("ID"), release.get("ID_LIKE"))))
            pretty = release.get("PRETTY_NAME", "")
        euid = os.geteuid() if hasattr(os, "geteuid") else None
        return cls(name, distro, pretty or f"{name} {platform.release()}", euid, dict(os.environ))


def _os_release(path: str = "/etc/os-release") -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return values


# --- how to install ------------------------------------------------------------------------------

_LINUX = {
    # family -> (command, nmap package, ssh client package)
    "debian": ("sudo apt install", "nmap", "openssh-client"),
    "ubuntu": ("sudo apt install", "nmap", "openssh-client"),
    "fedora": ("sudo dnf install", "nmap", "openssh-clients"),
    "rhel": ("sudo dnf install", "nmap", "openssh-clients"),
    "centos": ("sudo dnf install", "nmap", "openssh-clients"),
    "arch": ("sudo pacman -S", "nmap", "openssh"),
    "alpine": ("sudo apk add", "nmap", "openssh-client"),
    "suse": ("sudo zypper install", "nmap", "openssh-clients"),
    "opensuse": ("sudo zypper install", "nmap", "openssh-clients"),
}


def tools_hint(tool: str) -> str:
    """How to get one of the ProjectDiscovery tools (single binaries, no admin needed)."""
    return f"zues tools install {tool}   (pinned release, SHA-256 checked, no admin)"


def install_hint(tool: str, system: System) -> str:
    """The command that installs `tool` here (system packages are left to the user)."""
    if tool in ("nuclei", "subfinder", "nuclei-templates"):
        return tools_hint(tool)
    if system.name == "Linux":
        for family in system.distro.split():
            if family in _LINUX:
                command, nmap, ssh = _LINUX[family]
                return f"{command} {nmap if tool == 'nmap' else ssh}"
        return f"install {tool} with your distribution's package manager"
    if system.name == "Darwin":
        return "brew install nmap" if tool == "nmap" else "ssh is part of macOS"
    if system.name == "Windows":
        if tool == "nmap":
            return "winget install Insecure.Nmap   (installs Npcap too; or: choco install nmap)"
        return "Settings > Apps > Optional features > OpenSSH Client"
    return f"install {tool} (see its website)"


# --- the checks ----------------------------------------------------------------------------------


def check_nmap(path: str | None, version: str | None, system: System) -> Check:
    if path is None:
        hidden = _windows_nmap(system)
        if hidden:
            return Check(
                "nmap",
                WARN,
                f"installed at {hidden} but not on PATH",
                "open a new terminal (the installer changed PATH), or add that folder to PATH",
                required=True,
            )
        return Check("nmap", MISSING, "not found", install_hint("nmap", system), required=True)
    return Check("nmap", OK, f"{version or 'version unknown'} ({path})", required=True)


def _windows_nmap(system: System) -> str | None:
    if system.name != "Windows":
        return None
    for root in (system.env.get("ProgramFiles(x86)"), system.env.get("ProgramFiles")):
        if root and Path(root, "Nmap", "nmap.exe").is_file():
            return str(Path(root, "Nmap", "nmap.exe"))
    return None


def check_nmap_rights(path: str | None, system: System, capability: bytes | None) -> Check:
    """Can nmap open raw sockets (SYN scan, traceroute)? `capability`: the binary's
    security.capability attribute on Linux, if any."""
    name = "nmap rights"
    if path is None:
        return Check(name, INFO, "nmap not found")
    fallback = "without them nmap falls back to a TCP connect scan and cannot traceroute"
    if system.name == "Windows":
        npcap = Path(system.env.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
        if npcap.is_dir():
            return Check(name, OK, "Npcap is installed (raw packets)")
        return Check(name, WARN, f"Npcap not found: {fallback}", "install Npcap: https://npcap.com")
    if system.euid == 0:
        return Check(name, OK, "running as root")
    if system.name == "Linux" and _has_cap_net_raw(capability):
        if system.env.get("NMAP_PRIVILEGED"):
            return Check(name, OK, "file capability cap_net_raw, NMAP_PRIVILEGED set")
        return Check(
            name,
            WARN,
            "nmap has cap_net_raw but NMAP_PRIVILEGED is not set, so it will not use it",
            "export NMAP_PRIVILEGED=1",
        )
    hint = (
        f"sudo setcap cap_net_raw+eip {path}  and  export NMAP_PRIVILEGED=1  (or run as root)"
        if system.name == "Linux"
        else "run ZuesScan with sudo"
    )
    return Check(name, WARN, f"no raw-socket rights: {fallback}", hint)


def _has_cap_net_raw(capability: bytes | None) -> bool:
    """vfs_cap_data: a 32-bit magic, then the low 32 permitted bits (little endian)."""
    if not capability or len(capability) < 8:
        return False
    permitted = int.from_bytes(capability[4:8], "little")
    return bool(permitted >> CAP_NET_RAW & 1)


def check_tool(name: str, path: str | None, version: str | None, system: System) -> Check:
    if path is None:
        return Check(name, MISSING, "not found (optional)", install_hint(name, system))
    return Check(name, OK, f"{version or 'version unknown'} ({path})")


def check_templates(pinned: str | None, version: str | None, home: Path) -> Check:
    name = "nuclei templates"
    if pinned:
        if not Path(pinned).is_dir():
            return Check(name, ERROR, f"{pinned} does not exist", tools_hint("nuclei-templates"))
        return Check(name, OK, f"{version or 'version unknown'}, pinned ({pinned})")
    own = home / "nuclei-templates"
    if own.is_dir():
        return Check(
            name,
            INFO,
            f"nuclei's own copy ({own}), not pinned: runs are not reproducible",
            tools_hint("nuclei-templates"),
        )
    return Check(
        name,
        WARN,
        "none: nuclei would download templates during the first scan",
        tools_hint("nuclei-templates"),
    )


def provider_keys(text: str) -> int:
    """How many sources have at least one key in a subfinder provider config: subfinder
    writes every source with an empty list (`crtsh: []`) on its first run."""
    sources = 0
    current_has_key = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[0].isspace() and stripped.endswith(":"):  # a source with a list below
            sources += current_has_key
            current_has_key = False
        elif stripped.startswith("- ") and stripped[2:].strip():
            current_has_key = True
        elif not line[0].isspace():  # `source: []` or `source: [key]`
            sources += current_has_key
            current_has_key = False
            value = stripped.partition(":")[2].strip()
            if value.startswith("[") and value.strip("[] "):
                sources += 1
    return sources + current_has_key


def check_providers(path: str | None) -> Check:
    if path:
        try:
            keys = provider_keys(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            return Check("subfinder keys", ERROR, f"cannot read {path}: {exc}")
        if keys:
            return Check("subfinder keys", OK, f"{keys} source(s) with API keys ({path})")
        return Check(
            "subfinder keys",
            INFO,
            f"{path} holds no API key: only subfinder's free sources answer",
            "add keys to it (see subfinder's documentation)",
        )
    return Check(
        "subfinder keys",
        INFO,
        "no provider config: only subfinder's free sources answer",
        "put API keys in ~/.config/subfinder/provider-config.yaml or use --subfinder-config",
    )


def check_cve_cache(path: str, now: datetime) -> Check:
    name = "CVE data"
    if not Path(path).is_file():
        return Check(
            name,
            INFO,
            f"no NVD cache at {path}: CVE matching uses the small bundled seed",
            f"zues cve sync --cache {path}",
        )
    from zues_scan.cve.cache import CacheError, CveCache

    try:
        with CveCache(path) as cache:
            status = cache.status()
    except (CacheError, sqlite3.Error) as exc:
        return Check(name, ERROR, f"{path}: {exc}", f"zues cve sync --cache {path} --full")
    synced = [datetime.fromisoformat(at) for at in status.scopes.values()]
    if not synced:
        return Check(name, WARN, f"{path} was never synced", f"zues cve sync --cache {path}")
    age = (now - max(synced)).days
    detail = f"{status.cves} CVEs, synced {age} day(s) ago ({path})"
    if age > CACHE_STALE_DAYS:
        return Check(name, WARN, detail, f"zues cve sync --cache {path}")
    return Check(name, OK, detail)


def check_server_extra(missing: list[str]) -> Check:
    if missing:
        return Check(
            "service extra",
            INFO,
            f"not installed ({', '.join(missing)}): only needed for worker, scheduler, web",
            "pip install 'zues-scan[server]'",
        )
    return Check("service extra", OK, "FastAPI, uvicorn, Redis, RQ")


def check_service(config_path: str) -> list[Check]:
    """service.toml, its database and its Redis.

    The configuration is checked even without the server extra (it is plain TOML): a
    file can be prepared and checked on a machine that will not run the service.
    """
    from zues_scan.server.config import ConfigError, load_config

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        return [Check("service config", ERROR, str(exc), required=True)]
    checks = [Check("service config", OK, f"{config_path}: {len(config.targets)} target(s)")]
    db = Path(config.db)
    if not db.is_file():
        checks.append(Check("database", INFO, f"{db} does not exist yet (first scan creates it)"))
    else:
        try:
            conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
            conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            conn.close()
            checks.append(Check("database", OK, str(db)))
        except sqlite3.Error as exc:
            checks.append(Check("database", ERROR, f"{db}: {exc}", required=True))
    try:
        from zues_scan.server import queue
    except ImportError as exc:
        checks.append(
            Check(
                "redis",
                ERROR,
                f"cannot check Redis: the server extra is not installed ({exc})",
                "pip install 'zues-scan[server]'",
                required=True,
            )
        )
        return checks
    try:
        queue.connect(config).ping()
        checks.append(Check("redis", OK, queue.safe_url(config.redis_url)))
    except queue.UNREACHABLE as exc:
        checks.append(
            Check(
                "redis",
                ERROR,
                f"cannot reach {queue.safe_url(config.redis_url)}: {exc}",
                "start Redis (docker compose up -d redis) or fix redis_url",
                required=True,
            )
        )
    return checks


# --- gathering the facts -------------------------------------------------------------------------


def _version(command: list[str]) -> str | None:
    """First line of `<tool> --version`-like output that has a version number in it."""
    import re

    try:
        proc = subprocess.run(
            command, capture_output=True, encoding="utf-8", errors="replace", timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+\.\d+(?:\.\d+)*)", proc.stdout + proc.stderr)
    return match.group(1) if match else None


def gather(config: str | None = None, cve_cache: str = "zues-cve.db") -> list[Check]:
    from zues_scan.plugins.nuclei import NucleiPlugin, default_templates, templates_version
    from zues_scan.plugins.subfinder import SubfinderPlugin

    system = System.current()
    checks: list[Check] = []
    nmap = tools.which("nmap")
    checks.append(check_nmap(nmap, _version([nmap, "--version"]) if nmap else None, system))
    capability = None
    if nmap and system.name == "Linux" and hasattr(os, "getxattr"):
        try:
            capability = os.getxattr(os.path.realpath(nmap), "security.capability")
        except OSError:
            capability = None
    checks.append(check_nmap_rights(nmap, system, capability))
    pinned = default_templates()
    nuclei = tools.which("nuclei")
    checks.append(
        check_tool(
            "nuclei", nuclei, NucleiPlugin(templates=pinned).version() if nuclei else None, system
        )
    )
    checks.append(
        check_templates(pinned, templates_version(pinned) if pinned else None, Path.home())
    )
    subfinder = tools.which("subfinder")
    plugin = SubfinderPlugin()
    checks.append(
        check_tool("subfinder", subfinder, plugin.version() if subfinder else None, system)
    )
    checks.append(check_providers(os.environ.get("ZUES_SUBFINDER_CONFIG") or plugin.providers()))
    ssh = shutil.which("ssh")
    checks.append(check_tool("ssh", ssh, _version(["ssh", "-V"]) if ssh else None, system))
    checks.append(check_cve_cache(cve_cache, datetime.now(UTC)))
    missing = []
    for module in ("fastapi", "uvicorn", "redis", "rq"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    checks.append(check_server_extra(missing))
    checks += check_plugins()
    if config:
        checks += check_service(config)
    return checks


def check_plugins() -> list[Check]:
    """Plugins from installed packages: loadable, and is the program they run here?"""
    from zues_scan.plugins import registry

    loaded = registry.load()
    checks = [Check("plugins", ERROR, problem) for problem in loaded.problems]
    for spec in loaded.plugins.values():
        if spec.source == "built-in":
            continue  # checked one by one above
        if spec.binary and shutil.which(spec.binary) is None:
            checks.append(
                Check(
                    f"plugin {spec.name}",
                    MISSING,
                    f"needs the program {spec.binary!r} (from {spec.source})",
                    f"install {spec.binary}, see the documentation of {spec.source}",
                )
            )
        else:
            checks.append(
                Check(f"plugin {spec.name}", OK, f"{spec.kind}, {spec.activity} ({spec.source})")
            )
    return checks


# --- output --------------------------------------------------------------------------------------


def header(system: System | None = None) -> str:
    system = system or System.current()
    return f"ZuesScan {__version__} on {system.pretty}, Python {platform.python_version()}"


def render(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = []
    for c in checks:
        lines.append(f"  {c.status:<8} {c.name:<{width}}  {c.detail}")
        if c.hint and c.status != OK:
            lines.append(f"  {'':<8} {'':<{width}}  -> {c.hint}")
    blocking = [c.name for c in checks if c.blocking]
    if blocking:
        lines.append(f"\nnot ready: {', '.join(blocking)} must be fixed before any scan")
    else:
        warnings = sum(1 for c in checks if c.status in (WARN, MISSING, ERROR))
        lines.append(
            "\nready to scan"
            + (f" ({warnings} thing(s) above would make scans better)" if warnings else "")
        )
    return "\n".join(lines)


def as_json(checks: list[Check]) -> dict[str, Any]:
    return {
        "version": __version__,
        "python": platform.python_version(),
        "platform": sys.platform,
        "ready": not any(c.blocking for c in checks),
        "checks": [asdict(c) for c in checks],
    }
