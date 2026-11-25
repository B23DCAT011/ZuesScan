"""Which plugins exist, what each one does, and how to build it for a scan.

A plugin is described by a `PluginSpec`: its name, its kind (`scanner` finds hosts and
services, `check` tests what was found, `discovery` finds names to scan), how far it
goes with a target (`activity`, held against the scope's `@activity`), the program it
needs, and a factory that builds it from the scan's settings (`PluginContext`).

The built-in plugins are listed here. Others come from installed packages, through
the `zues_scan.plugins` entry point group — nothing in ZuesScan changes to add one:

    # pyproject.toml of a plugin package
    [project.entry-points."zues_scan.plugins"]
    exposed-git = "zues_exposed_git:PLUGIN"     # a PluginSpec

A package that fails to load, or that claims a built-in name, is reported and left out;
it never stops the built-in plugins from working. See docs/PLUGINS.md.

Loading a plugin runs its code with every right ZuesScan has (G25). A `Policy` says which
packages may do that: the service loads only the plugins its configuration pins — by
package, version and the SHA-256 of the files that package installed, checked *before*
anything of it is imported — and it trusts the `activity` its operator wrote down, not the
one the plugin claims. Without a policy (a person's own `zues scan`) every installed
plugin loads, as installing it was the decision.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from importlib import metadata
from pathlib import Path
from typing import Any, Literal

from zues_scan.cve.cache import CveCache
from zues_scan.plugins import interactsh
from zues_scan.plugins.base import ScanError
from zues_scan.plugins.dnsx import DnsxPlugin
from zues_scan.plugins.httpx import HttpxPlugin
from zues_scan.plugins.naabu import NaabuPlugin
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.plugins.nuclei import NucleiPlugin
from zues_scan.plugins.ssh_packages import SshCredential, SshPackagesPlugin
from zues_scan.plugins.subfinder import SubfinderPlugin
from zues_scan.profiles import BUILTIN as BUILTIN_PROFILES
from zues_scan.profiles import DEFAULT_PROFILE, ScanProfile
from zues_scan.scope import Activity, ScopeError

GROUP = "zues_scan.plugins"
Kind = Literal["scanner", "check", "discovery"]
KINDS: tuple[Kind, ...] = ("scanner", "check", "discovery")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")


class PluginError(Exception):
    """A plugin cannot be used as asked (unknown name, wrong kind, missing setting)."""


@dataclass(frozen=True)
class PluginContext:
    """What a factory may use to build a plugin for one scan."""

    profile: ScanProfile = field(default_factory=lambda: BUILTIN_PROFILES[DEFAULT_PROFILE])
    nuclei_templates: str | None = None
    subfinder_config: str | None = None
    dns_wordlist: str | None = None
    credentials: list[SshCredential] | None = None
    cve_cache: CveCache | None = None


@dataclass(frozen=True)
class PluginSpec:
    name: str
    kind: Kind
    activity: Activity
    summary: str
    factory: Callable[[PluginContext], Any]
    binary: str | None = None  # the program it runs, if any (for `zues plugins`, doctor)
    needs: tuple[str, ...] = ()  # e.g. "raw sockets", "credentials", "Internet"
    source: str = "built-in"  # or the package an entry point came from

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise PluginError(f"plugin name {self.name!r}: lowercase letters, digits and -")
        if self.kind not in KINDS:
            raise PluginError(f"plugin {self.name}: kind must be one of {', '.join(KINDS)}")
        if not isinstance(self.activity, Activity):
            raise PluginError(f"plugin {self.name}: activity must be a zues_scan.scope.Activity")


# --- the built-in plugins -----------------------------------------------------------------------
# Factories look the classes up when called, so that tests can replace them.


def _nmap(ctx: PluginContext) -> Any:
    return NmapPlugin(profile=ctx.profile)


def _httpx(ctx: PluginContext) -> Any:
    return HttpxPlugin(profile=ctx.profile)


def _naabu(ctx: PluginContext) -> Any:
    return NaabuPlugin(profile=ctx.profile, nmap=lambda *a, **kw: NmapPlugin(*a, **kw))


def _nuclei(ctx: PluginContext) -> Any:
    # The interactsh server comes from the environment, not the context: the context is
    # handed to third-party plugins, and the server's token is not theirs to see.
    try:
        server = interactsh.from_env()
    except interactsh.InteractshError as exc:
        raise PluginError(f"nuclei: {exc}") from exc
    return NucleiPlugin(profile=ctx.profile, templates=ctx.nuclei_templates, interactsh=server)


def _subfinder(ctx: PluginContext) -> Any:
    return SubfinderPlugin(provider_config=ctx.subfinder_config)


def _dnsx(ctx: PluginContext) -> Any:
    return DnsxPlugin(wordlist=ctx.dns_wordlist, rate=ctx.profile.check_rate or 100)


def _ssh_packages(ctx: PluginContext) -> Any:
    if not ctx.credentials or ctx.cve_cache is None:
        raise PluginError(
            "ssh-packages needs --credentials and --cve-cache with Debian tracker data "
            "(zues cve sync --debian <release>)"
        )
    return SshPackagesPlugin(ctx.credentials, ctx.cve_cache)


BUILTINS: tuple[PluginSpec, ...] = (
    PluginSpec(
        "nmap",
        "scanner",
        NmapPlugin.activity,
        "port and service scan, traceroute (IPv4 + IPv6)",
        _nmap,
        binary="nmap",
        needs=("raw sockets for SYN scan and traceroute",),
    ),
    PluginSpec(
        "naabu",
        "scanner",
        NaabuPlugin.activity,
        "fast port discovery (connect scan), then nmap on the open ports only",
        _naabu,
        binary="naabu",
        needs=("nmap for service names and versions",),
    ),
    PluginSpec(
        "nuclei",
        "check",
        NucleiPlugin.activity,
        "template checks on the services found (web, SSH, Redis, ...)",
        _nuclei,
        binary="nuclei",
        needs=("nuclei templates",),
    ),
    PluginSpec(
        "httpx",
        "check",
        HttpxPlugin.activity,
        "web services: status, title, server, technologies (versions go to the CVE stage)",
        _httpx,
        binary="httpx",
    ),
    PluginSpec(
        "ssh-packages",
        "check",
        SshPackagesPlugin.activity,
        "installed Debian packages vs the Debian Security Tracker, over SSH",
        _ssh_packages,
        binary="ssh",
        needs=("credentials", "CVE cache with Debian data"),
    ),
    PluginSpec(
        "subfinder",
        "discovery",
        SubfinderPlugin.activity,
        "subdomains from public sources",
        _subfinder,
        binary="subfinder",
        needs=("Internet",),
    ),
    PluginSpec(
        "dnsx",
        "discovery",
        DnsxPlugin.activity,
        "subdomains from a wordlist, confirmed in DNS",
        _dnsx,
        binary="dnsx",
        needs=("a DNS resolver",),
    ),
)


# --- which third-party plugins may load (G25) ---------------------------------------------------

PINS_ENV = "ZUES_PLUGINS"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PACKAGE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}")
# Files an installer writes, not the package's author: they differ from one install of the
# same release to the next (pip or uv, where it came from) and hold no code.
_INSTALLER_FILES = frozenset(
    {"RECORD", "RECORD.jws", "RECORD.p7s", "INSTALLER", "REQUESTED", "direct_url.json"}
)
_PIN_KEYS = ("name", "package", "version", "sha256", "activity")


class PinError(PluginError):
    """A package's installed files cannot be pinned, or do not match their pin."""


def normalize(package: str) -> str:
    """A package name as pip compares them (PEP 503): Zues_Exposed.Git -> zues-exposed-git."""
    return re.sub(r"[-_.]+", "-", package).lower()


@dataclass(frozen=True)
class Pin:
    """One third-party plugin a service may load, exactly as it was reviewed."""

    name: str  # the plugin's (entry point's) name
    package: str  # the package that provides it
    version: str
    sha256: str  # of the files that package installed (`package_digest`)
    activity: Activity  # what its operator judged it does: the scope gate uses this

    def line(self) -> str:
        """As one ZUES_PLUGINS item."""
        return f"{self.name}:{self.activity}:{self.package}=={self.version}:{self.sha256}"

    def wire(self) -> dict[str, str]:
        """As the child process that runs the plugin receives it (to check it again)."""
        return {
            "name": self.name,
            "package": self.package,
            "version": self.version,
            "sha256": self.sha256,
            "activity": str(self.activity),
        }

    def toml(self) -> str:
        """As a [[plugins]] table of service.toml."""
        return (
            "[[plugins]]\n"
            f'name = "{self.name}"\n'
            f'package = "{self.package}"\n'
            f'version = "{self.version}"\n'
            f'sha256 = "{self.sha256}"\n'
            f'activity = "{self.activity}"\n'
        )


@dataclass(frozen=True)
class Policy:
    """Which third-party plugins may load. No pins: the built-in plugins only."""

    pins: tuple[Pin, ...] = ()
    where: str = "the service configuration"  # where to allow one, for messages

    def pin(self, name: str) -> Pin | None:
        return next((p for p in self.pins if p.name == name), None)


def make_pin(name: str, activity: str, package: str, version: str, sha256: str, where: str) -> Pin:
    """A pin from its five settings, checked; `where` prefixes each message."""
    if not _NAME.fullmatch(name):
        raise PluginError(f"{where}: plugin name {name!r}: lowercase letters, digits and -")
    if name in {spec.name for spec in BUILTINS}:
        raise PluginError(f"{where}: {name} is built in: only other packages' plugins are pinned")
    try:
        granted = Activity.parse(activity)
    except ScopeError as exc:
        raise PluginError(f"{where}: {exc}") from None
    if not _PACKAGE.fullmatch(package):
        raise PluginError(f"{where}: package {package!r} is not a package name")
    if not _VERSION.fullmatch(version):
        raise PluginError(f"{where}: version {version!r} is not a release, e.g. 1.2.0")
    if not _HEX64.fullmatch(sha256):
        raise PluginError(
            f"{where}: sha256 must be 64 lowercase hex digits (zues plugins --pin {name})"
        )
    return Pin(name, package, version, sha256, granted)


def pin_from_table(raw: object, where: str) -> Pin:
    """One [[plugins]] table of service.toml."""
    if not isinstance(raw, dict):
        raise PluginError(f"{where}: must be a table")
    unknown = sorted(set(raw) - set(_PIN_KEYS))
    if unknown:
        raise PluginError(f"{where}: unknown setting(s) {', '.join(unknown)}")
    missing = [k for k in _PIN_KEYS if not isinstance(raw.get(k), str) or not raw[k].strip()]
    if missing:
        raise PluginError(
            f"{where}: needs {', '.join(missing)} (zues plugins --pin NAME prints them all)"
        )
    name, activity, package, version, sha256 = (
        raw[k].strip() for k in ("name", "activity", "package", "version", "sha256")
    )
    return make_pin(name, activity, package, version, sha256, where)


def pins_from_text(text: str, where: str = PINS_ENV) -> tuple[Pin, ...]:
    """ZUES_PLUGINS: `name:activity:package==version:sha256` items, separated by commas or
    spaces; `none` (or nothing): no third-party plugin."""
    items = [item for item in re.split(r"[,\s]+", text.strip()) if item]
    if items in ([], ["none"]):
        return ()
    pins = []
    for i, item in enumerate(items, start=1):
        parts = item.split(":")
        if len(parts) != 4 or "==" not in parts[2]:
            raise PluginError(
                f"{where} item {i} ({item[:40]!r}): write name:activity:package==version:sha256 "
                "(zues plugins --pin NAME prints it)"
            )
        package, _, version = parts[2].partition("==")
        pins.append(make_pin(parts[0], parts[1], package, version, parts[3], f"{where} item {i}"))
    return unique_pins(pins, where)


def unique_pins(pins: Iterable[Pin], where: str) -> tuple[Pin, ...]:
    seen: dict[str, Pin] = {}
    for pin in pins:
        if pin.name in seen:
            raise PluginError(f"{where}: two pins for the plugin {pin.name!r}")
        seen[pin.name] = pin
    return tuple(seen.values())


def policy_from_env(env: dict[str, str] | None = None) -> Policy | None:
    """The CLI's policy: ZUES_PLUGINS when it is set, else None (every installed plugin)."""
    text = ((os.environ if env is None else env).get(PINS_ENV) or "").strip()
    return Policy(pins_from_text(text), PINS_ENV) if text else None


def package_digest(dist: Any) -> str:
    """SHA-256 over the files a package installed, as its RECORD lists them: its code, its
    metadata, its entry points. Compiled caches, files outside the install folder (scripts
    the installer generates) and the installer's own records are left out: they differ
    between two installs of the same release.

    Reads the files only: nothing of the package is imported or run.
    """
    label = f"{dist.name} {dist.version}"
    paths = _record(dist)
    try:
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
    except ValueError:
        raise PinError(f"{label}: its direct_url.json is not JSON") from None
    if isinstance(direct, dict) and (direct.get("dir_info") or {}).get("editable"):
        raise PinError(
            f"{label} is an editable install: its code lives outside the installed files, "
            "so they cannot be pinned (install it without -e)"
        )
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        if _not_pinned(path):
            continue
        try:
            content = Path(dist.locate_file(path)).read_bytes()
        except OSError:
            raise PinError(f"{label}: an installed file is missing or unreadable: {path}") from None
        digest.update(path.encode() + b"\0" + hashlib.sha256(content).digest() + b"\n")
    return digest.hexdigest()


def _record(dist: Any) -> list[str]:
    """The paths a package's RECORD lists, read directly: `Distribution.files` drops the
    ones that no longer exist (Python 3.12+), which would hide a deleted file."""
    text = dist.read_text("RECORD")
    if text is None:
        raise PinError(
            f"{dist.name} {dist.version} was not installed from a wheel (it has no RECORD of "
            "its files): reinstall it with pip"
        )
    return [row[0].replace("\\", "/") for row in csv.reader(text.splitlines()) if row and row[0]]


def _not_pinned(path: str) -> bool:
    """Files outside the install folder (generated scripts, absolute paths), compiled
    caches, and what the installer writes about itself."""
    parts = path.split("/")
    return (
        parts[0] in ("..", "")
        or re.match(r"[A-Za-z]:", path) is not None
        or "__pycache__" in parts
        or path.endswith((".pyc", ".pyo"))
        or (len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] in _INSTALLER_FILES)
    )


def _modules(dist: Any) -> set[str]:
    """The top-level modules a package installed: what its entry points may name."""
    names: set[str] = set()
    for path in _record(dist):
        parts = path.split("/")
        if _not_pinned(path) or parts[0].endswith((".dist-info", ".data")):
            continue
        if len(parts) > 1:
            names.add(parts[0])
        elif parts[0].endswith(".py"):
            names.add(parts[0][:-3])
        elif parts[0].endswith((".so", ".pyd")):
            names.add(parts[0].split(".")[0])
    return names


def verify(entry: Any, pin: Pin) -> str:
    """Raises PinError unless `entry` comes from exactly the package `pin` names; returns
    the digest of its files. Decided from the installed files, before anything of the
    package is imported (by the registry, then again by the child process that runs it)."""
    dist = getattr(entry, "dist", None)
    if dist is None:
        raise PinError("its package cannot be identified, so it cannot be held to its pin")
    if normalize(dist.name) != normalize(pin.package):
        raise PinError(f"it comes from the package {dist.name}, the pin says {pin.package}")
    if dist.version != pin.version:
        raise PinError(
            f"{dist.name} {dist.version} is installed, the pin says {pin.version}: install "
            "the reviewed release, or review this one and pin it again"
        )
    digest = package_digest(dist)
    if digest != pin.sha256:
        raise PinError(
            f"the files of {dist.name} {dist.version} differ from the pinned ones "
            f"(sha256 {digest[:12]}…, pinned {pin.sha256[:12]}…): reinstall the reviewed "
            "release, or review what changed and pin it again"
        )
    module = entry.value.split(":")[0].split(".")[0].strip()
    if module not in _modules(dist):
        raise PinError(
            f"its entry point names the module {module!r}, which {dist.name} does not install"
        )
    return digest


def pin_for(name: str, entry_points: EntryPoints | None = None) -> Pin:
    """The pin of the installed plugin `name`, to review and paste into the configuration.

    Its activity is `active` — the most a plugin can do — until its operator, having read
    the code, writes down less: the plugin's own claim is never asked (that would run it).
    """
    if name in {spec.name for spec in BUILTINS}:
        raise PluginError(f"{name} is built in: only other packages' plugins are pinned")
    found = [e for e in (entry_points or _entry_points)() if e.name == name]
    if not found:
        raise PluginError(f"no installed package provides a plugin named {name!r}")
    packages = sorted({getattr(getattr(e, "dist", None), "name", "?") for e in found})
    if len(found) > 1:
        raise PluginError(f"several installed packages provide {name!r}: {', '.join(packages)}")
    [entry] = found
    dist = getattr(entry, "dist", None)
    if dist is None:
        raise PinError(f"the package of {name!r} cannot be identified")
    pin = make_pin(name, "active", dist.name, dist.version, package_digest(dist), f"plugin {name}")
    verify(entry, pin)  # its entry point names a module of its own package
    return pin


# --- the registry ---------------------------------------------------------------------------------


@dataclass
class Registry:
    plugins: dict[str, PluginSpec]
    problems: list[str] = field(default_factory=list)  # entry points that failed to load
    # Installed plugins a policy kept from loading (never imported): name -> why.
    left_out: dict[str, str] = field(default_factory=dict)
    # A pinned plugin's own claim, where its operator granted it more (`Pin.activity`).
    declared: dict[str, Activity] = field(default_factory=dict)

    def get(self, name: str, kind: Kind) -> PluginSpec:
        spec = self.plugins.get(name)
        if spec is None and name in self.left_out:
            raise PluginError(f"plugin {name} is not loaded: {self.left_out[name]}")
        if spec is None:
            known = ", ".join(n for n, s in self.plugins.items() if s.kind == kind) or "none"
            raise PluginError(f"unknown {kind} plugin {name!r} (available: {known})")
        if spec.kind != kind:
            raise PluginError(f"{name} is a {spec.kind} plugin, not a {kind}")
        return spec

    def build(self, names: list[str], kind: Kind, ctx: PluginContext) -> list[Any]:
        built = []
        for name in dict.fromkeys(names):  # each once, in the order asked
            spec = self.get(name, kind)
            declared = self.declared.get(name, spec.activity)
            plugin = spec.factory(ctx)
            if getattr(plugin, "name", None) is None:
                raise PluginError(f"plugin {name}: its factory built an object without a name")
            if getattr(plugin, "activity", declared) != declared:
                raise PluginError(f"plugin {name}: its activity differs from what it declares")
            if not hasattr(plugin, "activity"):
                try:
                    plugin.activity = declared  # what the scope gate reads
                except AttributeError:
                    pass
            if spec.activity != declared:
                plugin = _Granted(plugin, spec.activity)
            built.append(plugin)
        return built


class _Granted:
    """A plugin as its operator judged it: the scope gate reads the activity they granted,
    not the one the plugin claims. Everything else is the plugin's."""

    def __init__(self, plugin: Any, activity: Activity) -> None:
        self._plugin = plugin
        self.name = plugin.name
        self.activity = activity

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._plugin, attr)


EntryPoints = Callable[[], list[Any]]


def _entry_points() -> list[Any]:
    return list(metadata.entry_points(group=GROUP))


def spec_of(loaded: Any) -> PluginSpec:
    """What an entry point names: a PluginSpec, or a function returning one."""
    spec = loaded() if callable(loaded) and not isinstance(loaded, PluginSpec) else loaded
    if not isinstance(spec, PluginSpec):
        raise PluginError("the entry point must name a PluginSpec (or a function returning one)")
    return spec


# Specs read from child processes, by entry point and digest of the package's files: the
# same files give the same spec, so a service reads each one once, not on every request.
_DESCRIBED: dict[tuple[str, str, str], PluginSpec] = {}


def _package_spec(entry: Any, pin: Pin | None, digest: str | None, in_process: bool) -> PluginSpec:
    """The spec of a package's plugin. Read in a child process, whose factory builds a
    stand-in that runs every call of the plugin in a child too (`process`, G25); the
    package's code never runs here. `in_process` (tests only): import it here."""
    if in_process:
        return spec_of(entry.load())
    from zues_scan.plugins import process

    key = (entry.name, entry.value, digest) if digest is not None else None
    if key is not None and key in _DESCRIBED:
        return _DESCRIBED[key]
    dist = getattr(entry, "dist", None)
    root = getattr(dist, "locate_file", None)
    ref = process.Ref(
        entry.name,
        entry.value,
        pin.wire() if pin is not None else None,
        tuple(p for p in sys.path if p),
        (os.path.abspath(str(root(""))),) if root is not None else (),
    )
    try:
        facts = process.describe(ref)
    except ScanError as exc:
        raise PluginError(str(exc)) from None
    spec = PluginSpec(
        facts["name"],
        facts["kind"],
        facts["activity"],
        facts["summary"],
        process.factory(ref, facts["name"], facts["activity"]),
        binary=facts["binary"],
        needs=facts["needs"],
    )
    if key is not None:
        _DESCRIBED[key] = spec
    return spec


def load(
    entry_points: EntryPoints | None = None,
    policy: Policy | None = None,
    *,
    in_process: bool = False,
) -> Registry:
    """The built-in plugins and those installed packages declare.

    With a `policy`, a package's plugin loads only if the policy pins it and the installed
    files match the pin; anything else installed is left out without being imported.
    A package's plugin runs in child processes (`process`), never in this one.
    """
    registry = Registry({spec.name: spec for spec in BUILTINS})
    allowed_in = policy.where if policy is not None else ""
    seen: set[str] = set()
    for entry in (entry_points or _entry_points)():
        where = f"{entry.name} ({entry.value})"
        seen.add(entry.name)
        pin = None
        digest = None
        if policy is not None:
            if entry.name in registry.plugins:
                registry.problems.append(
                    f"plugin {where} left out: the name {entry.name!r} is already taken "
                    f"({registry.plugins[entry.name].source})"
                )
                continue
            pin = policy.pin(entry.name)
            package = getattr(getattr(entry, "dist", None), "name", None) or entry.value
            if pin is None:
                registry.left_out[entry.name] = (
                    f"installed (from {package}) but not allowed in {policy.where} "
                    f"(review it, then: zues plugins --pin {entry.name})"
                )
                continue
            try:
                digest = verify(entry, pin)
            except PinError as exc:
                registry.left_out[entry.name] = str(exc)
                registry.problems.append(f"plugin {where} left out: {exc}")
                continue
        try:
            spec = _package_spec(entry, pin, digest, in_process)
        except Exception as exc:  # noqa: BLE001 - a broken package must not break ZuesScan
            registry.problems.append(f"plugin {where} left out: {exc}")
            continue
        if spec.name in registry.plugins:
            registry.problems.append(
                f"plugin {where} left out: the name {spec.name!r} is already taken "
                f"({registry.plugins[spec.name].source})"
            )
            continue
        if pin is not None:
            reason = None
            if spec.name != pin.name:
                reason = f"it loads a plugin named {spec.name!r}, not {pin.name!r}"
            elif spec.activity > pin.activity:
                reason = (
                    f"it declares {spec.activity}, but {allowed_in} allows it as "
                    f"{pin.activity}: raise the pin's activity if you accept that"
                )
            if reason is not None:
                registry.left_out[pin.name] = reason
                registry.problems.append(f"plugin {where} left out: {reason}")
                continue
            if spec.activity != pin.activity:
                registry.declared[spec.name] = spec.activity
            spec = replace(spec, activity=pin.activity)
        dist = getattr(getattr(entry, "dist", None), "name", None)
        registry.plugins[spec.name] = replace(spec, source=dist or entry.value.split(":")[0])
    for wanted in policy.pins if policy is not None else ():
        if wanted.name not in seen:
            registry.problems.append(
                f"plugin {wanted.name} is allowed in {allowed_in} but no installed package "
                f"provides it (pip install {wanted.package}=={wanted.version})"
            )
    return registry
