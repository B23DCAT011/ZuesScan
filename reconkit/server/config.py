"""The service's configuration (`service.toml`), checked before anything starts.

The one rule that keeps the service from becoming a scanning proxy: **only targets
listed here can be scanned** — by the scheduler or through the API. A request names a
target by its `name`; it never brings its own address, scope file or options.

    [service]
    db = "/data/reconkit.db"
    cve_cache = "/data/reconkit-cve.db"    # optional: NVD data for the CVE stage
    redis_url = "redis://redis:6379/0"
    queue = "reconkit"

    [[tokens]]                     # who may use the API; `name` is recorded as operator
    name = "alice"
    sha256 = "9f86d08..."          # of the token (reconkit token), never the token
    role = "operator"              # "viewer": read only; "operator": scans, decisions

    [[targets]]
    name = "office-lan"
    target = "10.0.0.0/24"
    scope = "/config/scope-office.txt"
    profile = "full"
    every = "24h"                  # optional: scheduled scan (m, h or d)
    engagement = "PT-2026-014"
    nuclei = false

    [notify]
    webhook = "https://hooks.example.com/..."   # optional; Slack-compatible {"text": ...}
    min_priority = "P2"                          # new findings at least this urgent
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

ROLES = ("viewer", "operator")


class ConfigError(Exception):
    """The service configuration is invalid: the service must not start."""


@dataclass(frozen=True, slots=True)
class Token:
    name: str
    sha256: str
    role: str


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
    credentials: str | None = None
    ipv4_only: bool = False


@dataclass(frozen=True, slots=True)
class Notify:
    webhook: str | None = None
    min_priority: str = "P2"


@dataclass(frozen=True)
class ServiceConfig:
    path: str
    db: str
    redis_url: str = "redis://localhost:6379/0"
    queue: str = "reconkit"
    cve_cache: str | None = None
    tokens: tuple[Token, ...] = ()
    targets: dict[str, Target] = field(default_factory=dict)
    notify: Notify = Notify()

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


def load_config(path: str | Path) -> ServiceConfig:
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise ConfigError(f"service config not found: {path}") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read service config {path}: {exc}") from None
    _only(data, {"service", "tokens", "targets", "notify"}, str(path))
    service = data.get("service") or {}
    _only(service, {"db", "cve_cache", "redis_url", "queue"}, "[service]")
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
    return ServiceConfig(
        path=str(path),
        db=str(service["db"]),
        redis_url=str(service.get("redis_url", "redis://localhost:6379/0")),
        queue=str(service.get("queue", "reconkit")),
        cve_cache=service.get("cve_cache"),
        tokens=tokens,
        targets=targets,
        notify=Notify(webhook=webhook, min_priority=notify.get("min_priority", "P2")),
    )


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


def _target(raw: dict[str, Any], i: int) -> Target:
    where = f"[[targets]] #{i}"
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
        "credentials",
        "ipv4_only",
    }
    _only(raw, allowed, where)
    try:
        name, target, scope = str(raw["name"]), str(raw["target"]), str(raw["scope"])
    except KeyError as exc:
        raise ConfigError(f"{where}: missing {exc}") from None
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name):
        raise ConfigError(f"{where}: name {name!r}: lowercase letters, digits, - and _")
    if not Path(scope).is_file():
        raise ConfigError(f"{where} ({name}): scope file not found: {scope}")
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
        credentials=raw.get("credentials"),
        ipv4_only=bool(raw.get("ipv4_only", False)),
    )
