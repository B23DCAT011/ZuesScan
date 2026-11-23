"""The service's configuration (`service.toml`), checked before anything starts.

The one rule that keeps the service from becoming a scanning proxy: **only targets
listed here can be scanned** — by the scheduler or through the API. A request names a
target by its `name`; it never brings its own address, scope file or options.

    [service]
    db = "/data/zues.db"
    cve_cache = "/data/zues-cve.db"    # optional: NVD data for the CVE stage
    nuclei_templates = "/opt/nuclei-templates"   # optional (the image sets it already)
    subfinder_config = "/config/subfinder.yaml"  # optional: API keys of subfinder's sources
    dns_wordlist = "/config/words.txt"   # optional: dnsx's wordlist (default: ZuesScan's)
    redis_url = "redis://redis:6379/0"
    queue = "zues"

    [[tokens]]                     # who may use the API; `name` is recorded as operator
    name = "alice"
    sha256 = "9f86d08..."          # of the token (zues token), never the token
    role = "operator"              # "viewer": read only; "operator": scans, decisions

    [[targets]]
    name = "office-lan"
    target = "10.0.0.0/24"
    scope = "/config/scope-office.txt"
    profile = "full"
    every = "24h"                  # optional: scheduled scan (m, h or d)
    engagement = "PT-2026-014"
    nuclei = false                 # or: checks = ["nuclei"] (plugin names: zues plugins)
    discover_limit = 1000          # with discover = true: names considered at most

    [notify]
    webhook = "https://hooks.example.com/..."   # optional; Slack-compatible {"text": ...}
    min_priority = "P2"                          # new findings at least this urgent
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path
from typing import Any

ROLES = ("viewer", "operator", "admin")
# What each role may do includes what the roles before it may: an admin is an operator too.
RANK = {role: i for i, role in enumerate(ROLES)}
FILE, DASHBOARD = "file", "dashboard"  # where a target, scope or token is defined


NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")  # of a target or a dashboard scope


class ConfigError(Exception):
    """The service configuration is invalid: the service must not start."""


@dataclass(frozen=True, slots=True)
class Token:
    name: str
    sha256: str
    role: str
    source: str = FILE


@dataclass(frozen=True, slots=True)
class Target:
    name: str
    target: str
    scope: str
    profile: str = "standard"
    config: str | None = None  # TOML with more profiles
    every: timedelta | None = None
    engagement: str | None = None
    nuclei: bool = False
    discover: bool = False
    scanners: tuple[str, ...] = ()  # plugin names (zues plugins); empty: nmap
    checks: tuple[str, ...] = ()
    discoverers: tuple[str, ...] = ()
    credentials: str | None = None
    ipv4_only: bool = False
    discover_limit: int | None = None
    source: str = FILE  # FILE: service.toml; DASHBOARD: edited in the dashboard
    # A dashboard target's scope is a scope edited in the dashboard: `scope` is its name
    # and this its text. A file target's scope is the file at `scope`.
    scope_text: str | None = None


@dataclass(frozen=True, slots=True)
class Notify:
    webhook: str | None = None
    min_priority: str = "P2"


@dataclass(frozen=True)
class ServiceConfig:
    path: str
    db: str
    redis_url: str = "redis://localhost:6379/0"
    queue: str = "zues"
    cve_cache: str | None = None
    nuclei_templates: str | None = None
    subfinder_config: str | None = None
    dns_wordlist: str | None = None
    tokens: tuple[Token, ...] = ()
    targets: dict[str, Target] = field(default_factory=dict)
    notify: Notify = Notify()
    scopes: dict[str, str] = field(default_factory=dict)  # dashboard scopes: name -> text
    # Dashboard entries left out (e.g. a name service.toml took since): shown to admins.
    problems: tuple[str, ...] = ()
    managed_version: int = 0  # of the dashboard's configuration, when it was read

    def target(self, name: str) -> Target:
        try:
            return self.targets[name]
        except KeyError:
            raise ConfigError(f"no target named {name!r} in {self.path}") from None


def parse_every(text: str) -> timedelta:
    """ "30m", "6h", "1d" -> a timedelta; at least 5 minutes."""
    match = re.fullmatch(r"(\d+)\s*([mhd])", text.strip().lower())
    if match is None:
        raise ConfigError(f"every = {text!r}: write it like 30m, 6h or 1d")
    amount, unit = int(match.group(1)), match.group(2)
    delta = {
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }[unit]
    if delta < timedelta(minutes=5):
        raise ConfigError(f"every = {text!r}: at least 5 minutes between scheduled scans")
    return delta


ENVIRONMENT = "(environment)"  # the "path" of a configuration read from the environment


def config_path(given: str | None) -> str:
    """The configuration to use: `--config`, else $ZUES_CONFIG, else the environment."""
    return given or os.environ.get("ZUES_CONFIG") or ENVIRONMENT


def from_environment() -> ServiceConfig:
    """A service without service.toml: its settings from ZUES_* variables (the Docker
    image sets them), its targets, scopes and tokens from the dashboard (`zues user add`
    makes the first admin)."""
    env = os.environ
    min_priority = env.get("ZUES_NOTIFY_MIN_PRIORITY", "P2")
    if min_priority not in ("P1", "P2", "P3", "P4"):
        raise ConfigError("ZUES_NOTIFY_MIN_PRIORITY must be P1, P2, P3 or P4")
    webhook = env.get("ZUES_WEBHOOK") or None
    if webhook is not None and not webhook.startswith(("https://", "http://")):
        raise ConfigError("ZUES_WEBHOOK must be an http(s) URL")
    config = ServiceConfig(
        path=ENVIRONMENT,
        db=env.get("ZUES_DB") or "zues.db",
        redis_url=env.get("ZUES_REDIS_URL") or "redis://localhost:6379/0",
        queue=env.get("ZUES_QUEUE") or "zues",
        cve_cache=env.get("ZUES_CVE_CACHE") or None,
        notify=Notify(webhook=webhook, min_priority=min_priority),
    )
    return with_dashboard(config)


def load_config(path: str | Path | None = None) -> ServiceConfig:
    """service.toml at `path` (plus the dashboard's configuration); without a path, or
    with $ZUES_CONFIG's, see `config_path`; ENVIRONMENT: `from_environment()`."""
    path = config_path(str(path) if path is not None else None)
    if path == ENVIRONMENT:
        return from_environment()
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise ConfigError(f"service config not found: {path}") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read service config {path}: {exc}") from None
    _only(data, {"service", "tokens", "targets", "notify"}, str(path))
    service = data.get("service") or {}
    _only(
        service,
        {
            "db",
            "cve_cache",
            "redis_url",
            "queue",
            "nuclei_templates",
            "subfinder_config",
            "dns_wordlist",
        },
        "[service]",
    )
    if "db" not in service:
        raise ConfigError(f"{path}: [service] needs db = <path of the database>")
    tokens = tuple(_token(t, i) for i, t in enumerate(data.get("tokens", []), start=1))
    if len({t.name for t in tokens}) != len(tokens):
        raise ConfigError(f"{path}: two tokens have the same name")
    targets: dict[str, Target] = {}
    for i, raw in enumerate(data.get("targets", []), start=1):
        target = _target(raw, i)
        if target.name in targets:
            raise ConfigError(f"{path}: two targets are named {target.name!r}")
        targets[target.name] = target
    notify = data.get("notify") or {}
    _only(notify, {"webhook", "min_priority"}, "[notify]")
    if notify.get("min_priority", "P2") not in ("P1", "P2", "P3", "P4"):
        raise ConfigError("[notify] min_priority must be P1, P2, P3 or P4")
    webhook = notify.get("webhook")
    if webhook is not None and not str(webhook).startswith(("https://", "http://")):
        raise ConfigError("[notify] webhook must be an http(s) URL")
    config = ServiceConfig(
        path=str(path),
        db=str(service["db"]),
        redis_url=str(service.get("redis_url", "redis://localhost:6379/0")),
        queue=str(service.get("queue", "zues")),
        cve_cache=service.get("cve_cache"),
        nuclei_templates=service.get("nuclei_templates"),
        subfinder_config=service.get("subfinder_config"),
        dns_wordlist=service.get("dns_wordlist"),
        tokens=tokens,
        targets=targets,
        notify=Notify(webhook=webhook, min_priority=notify.get("min_priority", "P2")),
    )
    return with_dashboard(config)


def with_dashboard(config: ServiceConfig) -> ServiceConfig:
    """`config` plus the scopes, targets and tokens edited in the dashboard (stored in its
    database). service.toml wins a name both define; a dashboard entry that is no longer
    valid is left out and reported in `problems`, never fatal: the file decides whether
    the service starts."""
    if not Path(config.db).is_file():
        return config  # nothing edited yet (the database comes with the first scan)
    from zues_scan.storage import Storage, StorageError

    try:
        with Storage(config.db) as store:
            scopes = {row["name"]: row["content"] for row in store.managed_scopes()}
            target_rows = store.managed_targets()
            token_rows = store.managed_tokens()
            version = store.managed_version()
    except StorageError as exc:
        raise ConfigError(
            f"cannot read the dashboard's configuration in {config.db}: {exc}"
        ) from None
    problems: list[str] = []
    targets = dict(config.targets)
    for row in target_rows:
        name = row["name"]
        if name in targets:
            problems.append(f"dashboard target {name!r} left out: service.toml defines {name!r}")
            continue
        try:
            targets[name] = dashboard_target(name, json.loads(row["settings"]), scopes)
        except (ConfigError, ValueError) as exc:
            problems.append(f"dashboard target {name!r} left out: {exc}")
    tokens = list(config.tokens)
    taken = {t.name for t in tokens}
    for row in token_rows:
        if row["name"] in taken or row["role"] not in ROLES:
            problems.append(f"dashboard token {row['name']!r} left out: name taken or bad role")
            continue
        tokens.append(Token(row["name"], row["sha256"], row["role"], source=DASHBOARD))
    return replace(
        config,
        targets=targets,
        tokens=tuple(tokens),
        scopes=scopes,
        problems=tuple(problems),
        managed_version=version,
    )


# The settings a dashboard target may have: no server file paths (credentials, profile
# files), which only the person who runs the server should point at.
DASHBOARD_KEYS = (
    "target",
    "scope",
    "profile",
    "every",
    "engagement",
    "scanners",
    "checks",
    "discoverers",
    "discover",
    "discover_limit",
    "ipv4_only",
)


def dashboard_target(name: str, settings: dict[str, Any], scopes: dict[str, str]) -> Target:
    """A target edited in the dashboard, checked like one in service.toml."""
    if not isinstance(settings, dict):
        raise ConfigError("settings must be a table")
    _only(settings, set(DASHBOARD_KEYS), f"target {name!r}")
    return _target({"name": name, **settings}, 0, dashboard_scopes=scopes)


def _only(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")


def _token(raw: dict[str, Any], i: int) -> Token:
    where = f"[[tokens]] #{i}"
    if "token" in raw or "secret" in raw:
        # Checked first: the helpful message, not just "unknown key".
        raise ConfigError(f"{where}: store the token's sha256, never the token")
    _only(raw, {"name", "sha256", "role"}, where)
    try:
        name, digest, role = (
            str(raw["name"]),
            str(raw["sha256"]).lower(),
            str(raw.get("role", "viewer")),
        )
    except KeyError as exc:
        raise ConfigError(f"{where}: missing {exc}") from None
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ConfigError(f"{where}: sha256 must be 64 hex characters")
    if role not in ROLES:
        raise ConfigError(f"{where}: role must be one of {', '.join(ROLES)}")
    return Token(name, digest, role)


def _target(raw: dict[str, Any], i: int, dashboard_scopes: dict[str, str] | None = None) -> Target:
    where = f"[[targets]] #{i}" if dashboard_scopes is None else "target"
    allowed = {
        "name",
        "target",
        "scope",
        "profile",
        "config",
        "every",
        "engagement",
        "nuclei",
        "discover",
        "scanners",
        "checks",
        "discoverers",
        "credentials",
        "ipv4_only",
        "discover_limit",
    }
    _only(raw, allowed, where)
    try:
        name, target, scope = str(raw["name"]), str(raw["target"]), str(raw["scope"])
    except KeyError as exc:
        raise ConfigError(f"{where}: missing {exc}") from None
    if not NAME.fullmatch(name):
        raise ConfigError(f"{where}: name {name!r}: lowercase letters, digits, - and _")
    if not target.strip():
        raise ConfigError(f"{where} ({name}): target is empty")
    if dashboard_scopes is None:
        if not Path(scope).is_file():
            raise ConfigError(f"{where} ({name}): scope file not found: {scope}")
        source, scope_text = FILE, None
    else:
        if scope not in dashboard_scopes:
            raise ConfigError(f"{where} ({name}): no scope named {scope!r}")
        source, scope_text = DASHBOARD, dashboard_scopes[scope]
    engagement = raw.get("engagement")
    if engagement is not None and not isinstance(engagement, str):
        raise ConfigError(f"{where} ({name}): engagement must be text")
    return Target(
        name=name,
        target=target,
        scope=scope,
        profile=str(raw.get("profile", "standard")),
        config=raw.get("config"),
        every=parse_every(raw["every"]) if raw.get("every") else None,
        engagement=raw.get("engagement"),
        nuclei=bool(raw.get("nuclei", False)),
        discover=bool(raw.get("discover", False)),
        scanners=_names(raw.get("scanners"), f"{where} ({name}) scanners"),
        checks=_names(raw.get("checks"), f"{where} ({name}) checks"),
        discoverers=_names(raw.get("discoverers"), f"{where} ({name}) discoverers"),
        credentials=raw.get("credentials"),
        ipv4_only=bool(raw.get("ipv4_only", False)),
        discover_limit=_positive(raw.get("discover_limit"), f"{where} ({name}) discover_limit"),
        source=source,
        scope_text=scope_text,
    )


def _names(value: object, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(f'{what} must be a list of plugin names, e.g. ["nuclei"]')
    return tuple(value)


def _positive(value: object, what: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{what} must be a whole number of at least 1")
    return value
