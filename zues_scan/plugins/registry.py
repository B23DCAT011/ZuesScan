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
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Literal

from zues_scan.cve.cache import CveCache
from zues_scan.plugins.dnsx import DnsxPlugin
from zues_scan.plugins.naabu import NaabuPlugin
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.plugins.nuclei import NucleiPlugin
from zues_scan.plugins.ssh_packages import SshCredential, SshPackagesPlugin
from zues_scan.plugins.subfinder import SubfinderPlugin
from zues_scan.profiles import BUILTIN as BUILTIN_PROFILES
from zues_scan.profiles import DEFAULT_PROFILE, ScanProfile
from zues_scan.scope import Activity

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


def _naabu(ctx: PluginContext) -> Any:
    return NaabuPlugin(profile=ctx.profile, nmap=lambda *a, **kw: NmapPlugin(*a, **kw))


def _nuclei(ctx: PluginContext) -> Any:
    return NucleiPlugin(profile=ctx.profile, templates=ctx.nuclei_templates)


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


# --- the registry ---------------------------------------------------------------------------------


@dataclass
class Registry:
    plugins: dict[str, PluginSpec]
    problems: list[str] = field(default_factory=list)  # entry points that were left out

    def get(self, name: str, kind: Kind) -> PluginSpec:
        spec = self.plugins.get(name)
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
            plugin = spec.factory(ctx)
            if getattr(plugin, "name", None) is None:
                raise PluginError(f"plugin {name}: its factory built an object without a name")
            if getattr(plugin, "activity", spec.activity) != spec.activity:
                raise PluginError(f"plugin {name}: its activity differs from what it declares")
            if not hasattr(plugin, "activity"):
                try:
                    plugin.activity = spec.activity  # what the scope gate reads
                except AttributeError:
                    pass
            built.append(plugin)
        return built


EntryPoints = Callable[[], list[Any]]


def _entry_points() -> list[Any]:
    return list(metadata.entry_points(group=GROUP))


def load(entry_points: EntryPoints = _entry_points) -> Registry:
    """The built-in plugins and those installed packages declare."""
    registry = Registry({spec.name: spec for spec in BUILTINS})
    for entry in entry_points():
        where = f"{entry.name} ({entry.value})"
        try:
            loaded = entry.load()
            spec = loaded() if callable(loaded) and not isinstance(loaded, PluginSpec) else loaded
            if not isinstance(spec, PluginSpec):
                raise PluginError(
                    "the entry point must name a PluginSpec (or a function returning one)"
                )
        except Exception as exc:  # noqa: BLE001 - a broken package must not break ZuesScan
            registry.problems.append(f"plugin {where} left out: {exc}")
            continue
        if spec.name in registry.plugins:
            registry.problems.append(
                f"plugin {where} left out: the name {spec.name!r} is already taken "
                f"({registry.plugins[spec.name].source})"
            )
            continue
        dist = getattr(getattr(entry, "dist", None), "name", None)
        registry.plugins[spec.name] = _with_source(spec, dist or entry.value.split(":")[0])
    return registry


def _with_source(spec: PluginSpec, source: str) -> PluginSpec:
    return PluginSpec(
        spec.name,
        spec.kind,
        spec.activity,
        spec.summary,
        spec.factory,
        binary=spec.binary,
        needs=spec.needs,
        source=source,
    )
