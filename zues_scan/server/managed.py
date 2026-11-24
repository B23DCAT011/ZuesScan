"""Scopes, targets and tokens edited in the dashboard: checked here before they are kept.

service.toml stays what it was — written by whoever runs the server, read-only for the
dashboard. What an admin adds in the dashboard is stored in the database (schema 14)
and joins it (`config.with_dashboard`). Every change is one audit event in the hash
chain: who, when, what; a scope's text is kept by its SHA-256 like a run's scope.

The checks here are stricter than "the fields have the right type", because a target
saved now is scanned later, unattended:

- a scope must read as a scope file reads (same parser, same errors, line numbers);
- a target must be inside its scope — an address or range entirely allowed, a name
  allowed and resolving inside it (a DNS failure is a warning: it may resolve later),
  a discovery domain covered by a wildcard;
- every plugin must exist, be of the kind it is used as, and not go beyond the scope's
  `@activity` (nuclei needs `@activity active`);
- a scope still used by a target cannot be deleted, nor the last admin token.

The scan itself checks everything again (scope, time, activity): this only stops a
mistake from being saved.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from zues_scan.plugins import registry as plugin_registry
from zues_scan.profiles import BUILTIN as BUILTIN_PROFILES
from zues_scan.scope import ResolutionError, Resolver, Scope, ScopeError
from zues_scan.server.config import (
    DASHBOARD,
    NAME,
    RANK,
    ROLES,
    ConfigError,
    ServiceConfig,
    dashboard_target,
    target_patterns,
)

MAX_SCOPE_BYTES = 64 * 1024
TOKEN_NAME_CHARS = "lowercase letters, digits, and . _ @ -"


class ManagedError(ValueError):
    """What an admin asked to save is not valid; the message says why."""


class NotAllowed(ManagedError):
    """This admin may not take this decision (e.g. approve their own proposal)."""


@dataclass(frozen=True)
class Saved:
    """What was kept, and what the admin should know about it."""

    name: str
    warnings: list[str] = field(default_factory=list)
    proposal: int | None = None  # with scope_approval: the proposal waiting for approval


# --- scopes ------------------------------------------------------------------------------------


def read_scope(name: str, text: str) -> Scope:
    if not NAME.fullmatch(name):
        raise ManagedError(f"scope name {name!r}: lowercase letters, digits, - and _")
    if len(text.encode("utf-8")) > MAX_SCOPE_BYTES:
        raise ManagedError(f"a scope is at most {MAX_SCOPE_BYTES // 1024} KB")
    try:
        return Scope.from_text(text, f"scope {name}")
    except ScopeError as exc:
        raise ManagedError(str(exc)) from None


def describe_scope(scope: Scope) -> dict[str, Any]:
    """What a scope authorises, in a few fields, for the dashboard."""
    return {
        "allow": sorted(scope.allow_hosts)
        + [str(n) for n in scope.allow_nets]
        + sorted(f"*.{w}" for w in scope.allow_wildcards),
        "deny": sorted(scope.deny_hosts)
        + [str(n) for n in scope.deny_nets]
        + sorted(f"*.{w}" for w in scope.deny_wildcards),
        "activity": str(scope.activity),
        "expires": scope.expires.isoformat() if scope.expires else None,
        "windows": [w.text for w in scope.windows],
        "engagement": scope.engagement,
        "sha256": scope.sha256,
    }


def save_scope(
    store: Any,
    config: ServiceConfig,
    name: str,
    text: str,
    actor: str,
    reason: str | None = None,
) -> Saved:
    """Save a dashboard scope — or, with scope_approval, propose it (Saved.proposal)."""
    scope = read_scope(name, text)
    warnings = []
    if not (scope.allow_hosts or scope.allow_nets or scope.allow_wildcards):
        warnings.append("this scope allows nothing: every scan with it will be refused")
    proposal = None
    if config.scope_approval:
        proposal = store.propose_scope(
            name,
            action="save",
            content=scope.text,
            sha256=scope.sha256,
            reason=reason,
            actor=actor,
            at=_now(),
        )
    else:
        store.save_managed_scope(name, scope.text, scope.sha256, actor)
    # Targets already using it must still be inside it.
    for target in config.targets.values():
        if target.source == DASHBOARD and target.scope == name:
            try:
                _inside(scope, target.target, target.discover or bool(target.discoverers), None)
            except ManagedError as exc:
                warnings.append(f"target {target.name}: {exc}")
    return Saved(name, warnings, proposal)


def delete_scope(
    store: Any, config: ServiceConfig, name: str, actor: str, reason: str | None = None
) -> int | None:
    """Delete a dashboard scope — or, with scope_approval, propose it: the proposal's id."""
    _check_unused(config, name)
    if name not in config.scopes:
        raise LookupError(f"no dashboard scope named {name!r}")
    if config.scope_approval:
        return int(
            store.propose_scope(
                name,
                action="delete",
                content=None,
                sha256=None,
                reason=reason,
                actor=actor,
                at=_now(),
            )
        )
    if not store.delete_managed("scope", name, actor):
        raise LookupError(f"no dashboard scope named {name!r}")
    return None


def _check_unused(config: ServiceConfig, name: str) -> None:
    users = sorted(
        t.name for t in config.targets.values() if t.source == DASHBOARD and t.scope == name
    )
    if users:
        raise ManagedError(f"scope {name!r} is used by {', '.join(users)}: change them first")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --- two people for a scope change (G30) -------------------------------------------------------


def holders(config: ServiceConfig, name: str) -> list[str]:
    """Who may know the value of token `name`: its holder, whoever issued its value (made or
    last rotated it), whoever issued theirs, and so on. A token made by an admin is known to
    that admin until its holder rotates it."""
    tokens = {t.name: t for t in config.tokens}
    chain = [name]
    current = tokens.get(name)
    while current is not None and current.issued_by and current.issued_by not in chain:
        chain.append(current.issued_by)
        current = tokens.get(current.issued_by)
    return chain


def why_not_decide(config: ServiceConfig, proposal: Any, actor: str, decision: str) -> str | None:
    """Why `actor` may not take `decision` on `proposal` (None: they may)."""
    if decision == "withdraw":
        return None if actor == proposal["proposed_by"] else "only who proposed it can withdraw it"
    if actor == proposal["proposed_by"]:
        return "a second admin must decide on it, not who proposed it"
    if decision == "approve" and proposal["proposed_by"] in holders(config, actor):
        return (
            f"your token's value was issued by {proposal['proposed_by']}, who proposed this: "
            "rotate your own token first (Settings → Tokens → Rotate), so that only you know it"
        )
    return None


def decide_proposal(
    store: Any,
    config: ServiceConfig,
    proposal_id: int,
    decision: str,
    actor: str,
    note: str | None = None,
) -> Any:
    """Approve, reject or withdraw a scope proposal, by the rules above."""
    proposal = store.scope_proposal(proposal_id)
    if proposal is None:
        raise LookupError(f"no proposal #{proposal_id}")
    refused = why_not_decide(config, proposal, actor, decision)
    if refused:
        raise NotAllowed(refused)
    if decision == "reject" and not (note and note.strip()):
        raise ManagedError("say why it is rejected: the proposer and the audit trail need it")
    if decision == "approve":
        if proposal["action"] == "delete":
            _check_unused(config, proposal["name"])
        else:
            read_scope(proposal["name"], proposal["content"])  # still a valid scope
    return store.decide_scope_proposal(
        proposal_id, decision=decision, actor=actor, note=(note or "").strip() or None, at=_now()
    )


# --- targets -----------------------------------------------------------------------------------


def target_settings(body: dict[str, Any]) -> dict[str, Any]:
    """The settings to keep, from what the dashboard sent (empty values left out)."""
    settings: dict[str, Any] = {}
    for key in ("target", "scope", "profile", "every", "cron", "engagement"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            settings[key] = value.strip()
    for key in ("scanners", "checks", "discoverers"):
        names = body.get(key) or []
        if names:
            settings[key] = list(dict.fromkeys(str(n) for n in names))
    for key in ("discover", "ipv4_only"):
        if body.get(key):
            settings[key] = True
    if body.get("discover_limit") is not None:
        settings["discover_limit"] = body["discover_limit"]
    return settings


def save_target(
    store: Any,
    config: ServiceConfig,
    name: str,
    body: dict[str, Any],
    actor: str,
    resolver: Resolver | None = None,
) -> Saved:
    existing = config.targets.get(name)
    if existing is not None and existing.source != DASHBOARD:
        raise ManagedError(f"target {name!r} is defined in service.toml: change it there")
    settings = target_settings(body)
    try:
        target = dashboard_target(name, settings, config.scopes)
    except ConfigError as exc:
        raise ManagedError(str(exc)) from None
    if target.profile not in BUILTIN_PROFILES:
        known = ", ".join(BUILTIN_PROFILES)
        raise ManagedError(f"profile {target.profile!r}: one of {known}")
    if target.every is not None and target.every > timedelta(days=90):
        raise ManagedError("every: at most 90d between scheduled scans")
    scope = read_scope(target.scope, target.scope_text or "")
    registry = plugin_registry.load()
    plugins: list[tuple[str, Any]] = []
    try:
        for names, kind in (
            (target.scanners or ("nmap",), "scanner"),
            (target.checks, "check"),
            (target.discoverers or (("subfinder",) if target.discover else ()), "discovery"),
        ):
            for plugin in names:
                spec = registry.get(plugin, kind)  # type: ignore[arg-type]
                plugins.append((spec.name, spec.activity))
        scope.check_activity(plugins)
    except (plugin_registry.PluginError, ScopeError) as exc:
        raise ManagedError(str(exc)) from None
    discover = target.discover or bool(target.discoverers)
    warnings = _inside(scope, target.target, discover, resolver)
    not_ready = sorted(
        {n for n, _ in plugins if (s := registry.plugins[n]).binary and not _found(s.binary)}
    )
    if not_ready:
        warnings.append(
            f"not installed on this server: {', '.join(not_ready)} (zues doctor; the scan "
            "will be partial until they are)"
        )
    store.save_managed_target(name, settings, actor)
    return Saved(name, warnings)


def delete_target(store: Any, config: ServiceConfig, name: str, actor: str) -> None:
    existing = config.targets.get(name)
    if existing is not None and existing.source != DASHBOARD:
        raise ManagedError(f"target {name!r} is defined in service.toml: remove it there")
    if not store.delete_managed("target", name, actor):
        raise LookupError(f"no dashboard target named {name!r}")


def _inside(scope: Scope, target: str, discover: bool, resolver: Resolver | None) -> list[str]:
    """Refuse a target the scope does not cover; warnings for what only a scan can tell."""
    if discover:
        if not scope.allows_discovery(target.strip().lower().rstrip(".")):
            raise ManagedError(
                f"looking for names under {target!r} needs '*.{target}' (or a wider wildcard) "
                "in the scope"
            )
        return []
    try:
        scope.plan(target, resolver)
    except ResolutionError as exc:
        if _is_address(target):
            raise ManagedError(str(exc)) from None
        return [f"{target} does not resolve now ({exc}); it is checked again at every scan"]
    except ScopeError as exc:
        raise ManagedError(str(exc)) from None
    return []


def _is_address(target: str) -> bool:
    try:
        ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False
    return True


def _found(binary: str) -> bool:
    from zues_scan import tools

    return tools.which(binary) is not None


# --- tokens ------------------------------------------------------------------------------------


# How long a new token is accepted, unless asked otherwise: long enough not to be a chore,
# short enough that a forgotten or leaked one stops working by itself (G30).
DEFAULT_VALIDITY = timedelta(days=90)
MAX_VALIDITY = timedelta(days=730)


def expiry(valid_for: timedelta | None) -> str | None:
    """When a token made now stops being accepted (None: never), checked."""
    if valid_for is None:
        return None
    if not timedelta(days=1) <= valid_for <= MAX_VALIDITY:
        raise ManagedError("a token is valid for 1 day to 2 years (or without end)")
    return (datetime.now(UTC) + valid_for).isoformat(timespec="seconds")


def checked_targets(role: str, targets: list[str] | None) -> list[str] | None:
    """A token's target patterns, checked: none for an admin (it manages every target)."""
    if targets is None:
        return None
    try:
        patterns = target_patterns(targets, "targets")
    except ConfigError as exc:
        raise ManagedError(str(exc)) from None
    if role == "admin":
        raise ManagedError("an admin token sees every target: it cannot be limited to some")
    return list(patterns or ())


def set_token_targets(
    store: Any, config: ServiceConfig, name: str, targets: list[str] | None, actor: str
) -> None:
    """Limit a dashboard token to some targets (patterns), or (None) let it see them all.
    The change applies at its next request, sessions included."""
    token = next((t for t in config.tokens if t.name == name), None)
    if token is None or token.source != DASHBOARD:
        raise LookupError(f"no dashboard token named {name!r}")
    store.set_managed_token_targets(name, checked_targets(token.role, targets), actor)


def create_token(
    store: Any,
    config: ServiceConfig,
    name: str,
    role: str,
    actor: str,
    valid_for: timedelta | None = DEFAULT_VALIDITY,
    targets: list[str] | None = None,
) -> str:
    """Create a token; return it. Only its SHA-256 is kept: it is shown this once."""
    name = name.strip()
    if not name or len(name) > 64 or not all(c.isalnum() or c in "._@-" for c in name):
        raise ManagedError(f"token name {name!r}: {TOKEN_NAME_CHARS}, at most 64")
    if role not in ROLES:
        raise ManagedError(f"role must be one of {', '.join(ROLES)}")
    if any(t.name == name for t in config.tokens):
        raise ManagedError(f"a token named {name!r} exists already")
    expires_at = expiry(valid_for)
    limited = checked_targets(role, targets)
    token = secrets.token_urlsafe(32)
    store.save_managed_token(
        name, hashlib.sha256(token.encode()).hexdigest(), role, actor, expires_at, limited
    )
    return token


def rotate_token(
    store: Any,
    config: ServiceConfig,
    name: str,
    actor: str,
    valid_for: timedelta | None = DEFAULT_VALIDITY,
) -> str:
    """A new value for a dashboard token (same name and role); the old value, and every
    session opened with it, stop working at once. Return the new value (shown once)."""
    token = next((t for t in config.tokens if t.name == name), None)
    if token is None or token.source != DASHBOARD:
        raise LookupError(f"no dashboard token named {name!r}")
    expires_at = expiry(valid_for)
    value = secrets.token_urlsafe(32)
    store.rotate_managed_token(name, hashlib.sha256(value.encode()).hexdigest(), actor, expires_at)
    return value


def delete_token(store: Any, config: ServiceConfig, name: str, actor: str) -> None:
    token = next((t for t in config.tokens if t.name == name), None)
    if token is None or token.source != DASHBOARD:
        raise LookupError(f"no dashboard token named {name!r}")
    admins = [t for t in config.tokens if t.role == "admin" and t.name != name]
    if token.role == "admin" and not admins:
        raise ManagedError("this is the last admin token: create another admin first")
    store.delete_managed("token", name, actor)


def can(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]
