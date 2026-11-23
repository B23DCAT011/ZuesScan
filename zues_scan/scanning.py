"""One scan, from a request to a stored run — shared by the CLI and the worker.

`ScanSpec` says what to scan and how (target, scope file, profile, CVE data, extra
checks, who and under which engagement); `execute()` does all of it the one way
ZuesScan scans: load and check the inputs, open the database *before* probing
anything, run the pipeline, and record the result — a run, a failed run, or a refusal
in the audit trail. It returns an `Outcome` instead of printing, so the CLI prints it
and the worker reports it.

Exit codes (the CLI's): 0 done, 1 database / unexpected error, 2 bad input,
3 refused by the scope guard, 4 the scan failed (recorded as a failed run).
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zues_scan.audit import default_operator
from zues_scan.cve import CveDataError, CveSource, LocalCveSource
from zues_scan.cve.cache import CacheError, CveCache, NvdCveSource
from zues_scan.inventory_store import FindingEvent
from zues_scan.orchestrator import (
    DISCOVER_LIMIT,
    NoPluginAvailableError,
    Orchestrator,
    ScanRun,
    now,
)
from zues_scan.plugins import registry as plugin_registry
from zues_scan.plugins.base import CheckPlugin, ScanError
from zues_scan.plugins.nuclei import default_templates as nuclei_templates_default
from zues_scan.plugins.registry import PluginContext, PluginError
from zues_scan.plugins.ssh_packages import CredentialError, load_credentials
from zues_scan.plugins.subfinder import CONFIG_ENV as SUBFINDER_CONFIG_ENV
from zues_scan.profiles import DEFAULT_PROFILE, ProfileError, ScanProfile, load_profiles, override
from zues_scan.scope import ResolutionError, Scope, ScopeError
from zues_scan.storage import SCHEMA_VERSION, Storage, StorageError


@dataclass
class ScanSpec:
    """Everything one scan needs to know."""

    target: str
    scope: str  # path of the scope file (or, with scope_text, what names the scope)
    db: str = "zues.db"
    scope_text: str | None = None  # the scope itself, when it is not a file (dashboard)
    profile: str = DEFAULT_PROFILE
    config: str | None = None  # TOML file with more profiles
    overrides: dict[str, Any] = field(default_factory=dict)  # single profile settings
    no_cve: bool = False
    cve_db: str | None = None  # a CVE data JSON instead of the bundled seed
    cve_cache: str | None = None  # a local NVD cache
    credentials: str | None = None  # SSH keys for the authenticated package check
    # Plugins by name (see `zues plugins`); the flags below add the usual ones.
    scanners: list[str] = field(default_factory=list)  # empty: nmap
    checks: list[str] = field(default_factory=list)
    discoverers: list[str] = field(default_factory=list)
    nuclei: bool = False  # = checks += ["nuclei"]
    nuclei_templates: str | None = None  # default: $ZUES_NUCLEI_TEMPLATES
    discover: bool = False  # = discoverers += ["subfinder"]
    subfinder_config: str | None = None  # default: $ZUES_SUBFINDER_CONFIG
    dns_wordlist: str | None = None  # dnsx; default: ZuesScan's own list
    discover_limit: int | None = None
    ipv4_only: bool = False
    operator: str | None = None
    engagement: str | None = None


@dataclass
class Outcome:
    code: int
    run_id: int | None = None
    run: ScanRun | None = None
    # For the person (stderr in the CLI, the job result in the worker), in order.
    messages: list[str] = field(default_factory=list)
    changes: list[FindingEvent] = field(default_factory=list)


def resolve_profile(spec: ScanSpec) -> ScanProfile:
    profiles = load_profiles(spec.config)
    if spec.profile not in profiles:
        raise ProfileError(
            f"unknown profile {spec.profile!r}; choose one of: {', '.join(profiles)}"
        )
    return override(profiles[spec.profile], spec.overrides)


def execute(spec: ScanSpec) -> Outcome:
    """Run one scan as described by `spec`, and record what happened."""
    try:
        profile = resolve_profile(spec)
    except ProfileError as exc:
        return Outcome(2, messages=[f"error: {exc}"])
    try:
        if spec.scope_text is not None:
            scope = Scope.from_text(spec.scope_text, spec.scope)
        else:
            scope = Scope.from_file(spec.scope)
    except FileNotFoundError:
        return Outcome(2, messages=[f"error: scope file not found: {spec.scope}"])
    except ScopeError as exc:
        return Outcome(2, messages=[f"error: invalid scope file: {exc}"])

    scanner_names = list(spec.scanners) or ["nmap"]
    check_names = list(spec.checks)
    if spec.nuclei:
        check_names.append("nuclei")
    if spec.credentials:
        check_names.append("ssh-packages")
    discovery_names = list(spec.discoverers) or (["subfinder"] if spec.discover else [])
    registry = plugin_registry.load()
    notes = [f"warning: {problem}" for problem in registry.problems]

    with contextlib.ExitStack() as stack:
        cve_source: CveSource | None = None
        credentials = None
        try:
            cache = stack.enter_context(CveCache(spec.cve_cache)) if spec.cve_cache else None
            if cache is not None:
                cve_source = NvdCveSource(cache)
            elif not spec.no_cve:
                # The bundled seed unless another data file is given.
                cve_source = LocalCveSource(spec.cve_db) if spec.cve_db else LocalCveSource()
            if spec.credentials:
                if cache is None:
                    raise CacheError(
                        "--credentials needs --cve-cache with Debian tracker data "
                        "(zues cve sync --debian <release>)"
                    )
                credentials = load_credentials(spec.credentials)
        except (CveDataError, CacheError, CredentialError) as exc:
            return Outcome(2, messages=[f"error: {exc}"])
        templates = spec.nuclei_templates or nuclei_templates_default()
        if "nuclei" in check_names and templates and not Path(templates).is_dir():
            return Outcome(2, messages=[f"error: nuclei templates not found: {templates}"])
        providers = spec.subfinder_config or os.environ.get(SUBFINDER_CONFIG_ENV) or None
        if "subfinder" in discovery_names and providers and not Path(providers).is_file():
            return Outcome(2, messages=[f"error: subfinder config not found: {providers}"])
        if (
            "dnsx" in discovery_names
            and spec.dns_wordlist
            and not Path(spec.dns_wordlist).is_file()
        ):
            return Outcome(2, messages=[f"error: DNS wordlist not found: {spec.dns_wordlist}"])
        if spec.discover_limit is not None and spec.discover_limit < 1:
            return Outcome(2, messages=["error: --discover-limit must be at least 1"])
        context = PluginContext(
            profile=profile,
            nuclei_templates=templates,
            subfinder_config=providers,
            dns_wordlist=spec.dns_wordlist,
            credentials=credentials,
            cve_cache=cache,
        )
        try:
            scanners = registry.build(scanner_names, "scanner", context)
            checks: list[CheckPlugin] = registry.build(check_names, "check", context)
            discovery = registry.build(discovery_names, "discovery", context)
        except PluginError as exc:
            return Outcome(2, messages=[*notes, f"error: {exc}"])
        orch = Orchestrator(
            plugins=scanners,
            scope=scope,
            cve_source=cve_source,
            profile=profile,
            ipv4_only=spec.ipv4_only,
            operator=spec.operator or default_operator(),
            engagement=spec.engagement,
            discovery=discovery or None,
            checks=checks,
            discover_limit=spec.discover_limit or DISCOVER_LIMIT,
        )
        # Open the database before scanning: if the results cannot be saved, find out
        # now, not after probing the target for five minutes.
        try:
            store = Storage(spec.db)
        except StorageError as exc:
            return Outcome(1, messages=[f"error: {exc}"])
        with store:
            outcome = Outcome(0, messages=list(notes))
            if store.backup_path:
                outcome.messages.append(
                    f"note: database upgraded to schema v{SCHEMA_VERSION}; "
                    f"the previous version was kept at {store.backup_path}"
                )
            return _scan(spec, orch, store, outcome)


def _scan(spec: ScanSpec, orch: Orchestrator, store: Storage, outcome: Outcome) -> Outcome:
    say = outcome.messages.append
    started = now()
    try:
        run = orch.run(spec.target)
    except ScopeError as exc:
        # Refused before anything was probed: no run, but the refusal is on record.
        say(f"refused: {exc}")
        store.record_refusal(
            spec.target,
            str(exc),
            operator=orch.operator,
            engagement=orch.engagement,
            scope_sha256=orch.scope.sha256,
            scope_text=orch.scope.text,
        )
        outcome.code = 3
        return outcome
    except (NoPluginAvailableError, ResolutionError) as exc:
        say(f"scan failed: {exc}")
        return _record_failure(spec, orch, store, started, exc, outcome)
    except ScanError as exc:
        say(f"scan failed [{exc.plugin}]: {exc}")
        if exc.stderr:
            say(indent(exc.stderr))
        return _record_failure(spec, orch, store, started, exc, outcome)
    except RuntimeError as exc:
        say(f"error: {exc}")
        outcome.code = 1
        return outcome

    for note in run.notes:
        say(f"note: {note}")
    if run.skipped_plugins:
        say(f"warning: skipped unavailable scanners: {', '.join(run.skipped_plugins)}")
    if run.out_of_scope:
        dropped = ", ".join(run.out_of_scope)
        say(f"warning: a scanner reported hosts outside the scope; not saved: {dropped}")
    untraced = [a.host for a in run.assets if not a.route]
    if orch.profile is not None and orch.profile.traceroute and untraced:
        # Not an error: the scan itself is fine, only the map will lack these paths.
        say(
            f"note: no route recorded for {len(untraced)} of {len(run.assets)} host(s). "
            "Traceroute needs raw-socket privileges (root on Linux, Npcap on Windows), "
            "and a local target has no route."
        )
    outcome.run_id = store.save_run(run)
    outcome.run = run
    outcome.changes = store.changes_in_run(outcome.run_id)
    return outcome


def _record_failure(
    spec: ScanSpec,
    orch: Orchestrator,
    store: Storage,
    started: str,
    exc: Exception,
    outcome: Outcome,
) -> Outcome:
    """Store a failed scan as a `failed` run: no results, but the error is kept.

    Saving it as an ordinary empty run would read as "nothing found"; saving nothing
    would hide that the scan is broken.
    """
    run = orch.failed_run(spec.target, started, exc)
    run_id = store.save_run(run)
    outcome.messages.append(f"recorded as failed run #{run_id} in {spec.db} (no results saved)")
    if run.raw_outputs:
        outcome.messages.append(f"the scanner's output was kept: zues raw {run_id} --db {spec.db}")
    outcome.code, outcome.run_id, outcome.run = 4, run_id, run
    return outcome


def indent(text: str, prefix: str = "  | ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())
