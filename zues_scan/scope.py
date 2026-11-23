"""Scope guard — the safety/legal gate every scan must pass through first.

ZuesScan must only ever touch assets we own or are authorised to test. The scope is
an explicit **allowlist** of targets: exact hostnames, exact IPs, or CIDR ranges.
A target is permitted only if it matches an allow entry (and no deny entry). The
orchestrator refuses to scan anything that does not pass this gate.

The allowlist is loaded from a plain-text file, one entry per line:

    # lab targets
    scanme.lab
    10.0.0.0/24
    203.0.113.10
    !10.0.0.1          # deny takes precedence (leading '!')

`*.example.com` authorises every name *under* example.com (not example.com itself):
it is what lets discovered subdomains (subfinder) be scanned — each one still only if
every address it resolves to is in the allowlist. `!*.dev.example.com` denies a subtree.

`#` starts a comment anywhere on a line. Any entry that is not a valid IP, CIDR or
hostname is an error (with its line number) — never silently reinterpreted.

Lines starting with `@` state the terms of the authorisation itself (G21):

    @engagement PT-2026-014, signed 2026-11-01 by ACME IT    # recorded with each run
    @expires 2026-12-31 +07:00     # no scan after that day (offset: +07:00, default UTC)
    @window Mon-Fri 22:00-06:00 +07:00   # only then; repeatable; may cross midnight
    @activity active               # how far the testing may go (default: scan)

A scan outside the expiry date or every window is refused like an out-of-scope
target. An unknown directive is an error.

`@activity` is the ceiling the rules of engagement set, as each plugin declares what
it does: `passive` (asks third parties only — subfinder), `scan` (finds what is there:
port and service scans, read-only logins — nmap, the SSH package check), `active`
(tries flaws with crafted requests — nuclei). Without the directive, a scope allows
`scan`: a check that exploits must be authorised in writing, not by a command flag.

A hostname entry authorises the *name* only. Before a scan the name is resolved and
every address it points at must itself be in the allowlist (see `Scope.plan`), so a
scope that lists `scanme.lab` must also list the address or range it lives in.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from enum import IntEnum
from pathlib import Path

from zues_scan.schema import ScanTarget

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class Activity(IntEnum):
    """How far a plugin goes with a target; a scope sets the highest allowed."""

    PASSIVE = 0  # asks third parties only: nothing reaches the targets
    SCAN = 1  # finds what is there: port and service scans, read-only logins
    ACTIVE = 2  # tries flaws: crafted requests, exploitation checks

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Activity:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ScopeError(
                f"unknown activity {text.strip()!r} (known: passive, scan, active)"
            ) from None


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


class ResolutionError(Exception):
    """Raised when a hostname cannot be resolved, so there is nothing to check or scan."""


# A resolver maps a hostname to its addresses. Injectable so tests need no DNS.
Resolver = Callable[[str], list[str]]

# The largest IPv6 range ZuesScan will sweep: a /112. An IPv6 subnet is normally a /64
# (2^64 addresses): it cannot be swept, its hosts are found by name (DNS) instead.
MAX_IPV6_ADDRESSES = 2**16


def resolve_addresses(hostname: str) -> list[str]:
    """Resolve `hostname` to all of its IPv4 (A) and IPv6 (AAAA) addresses, IPv4 first."""
    return _lookup(hostname, socket.AF_UNSPEC)


def resolve_ipv4(hostname: str) -> list[str]:
    """Resolve `hostname` to its IPv4 addresses only (`scan --ipv4-only`)."""
    return _lookup(hostname, socket.AF_INET)


def _lookup(hostname: str, family: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, family=family)
    except socket.gaierror as exc:
        raise ResolutionError(f"cannot resolve {hostname!r}: {exc.strerror or exc}") from exc
    found = [str(info[4][0]) for info in infos if info[0] in (socket.AF_INET, socket.AF_INET6)]
    return sorted(dict.fromkeys(found), key=lambda a: ":" in a)  # IPv4 first, order kept


def _parse_net(entry: str) -> Network | None:
    """Parse an entry as an IP/CIDR network, or return None if it is a hostname."""
    try:
        # strict=False lets "10.0.0.0/24" and bare "203.0.113.10" both parse.
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


# One DNS label: letters, digits, '-' and '_' (no leading/trailing '-'), max 63 chars.
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


def _is_hostname(entry: str) -> bool:
    """True if `entry` is a syntactically valid hostname (no wildcard).

    An all-numeric last label is rejected: no real TLD is numeric, so "10.0.0.300"
    is a mistyped IP, not a hostname.
    """
    labels = entry.lower().split(".")
    if len(entry) > 253 or labels[-1].isdigit():
        return False
    return all(_LABEL.fullmatch(label) for label in labels)


def _contained(inner: Network, outer: Network) -> bool:
    """True if `inner` is a subnet of `outer` (same IP version only)."""
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


def _overlaps(a: Network, b: Network) -> bool:
    """True if `a` and `b` share at least one address (same IP version only)."""
    if a.version != b.version:
        return False
    return a.overlaps(b)


_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """When scanning is allowed: some days of the week, from `start` to `end`.

    An `end` before `start` crosses midnight: "Fri 22:00-06:00" runs from Friday 22:00
    to Saturday 06:00.
    """

    days: frozenset[int]  # 0 = Monday
    start: time
    end: time
    offset: timedelta  # the UTC offset the times are given in
    text: str  # as written, for messages

    def allows(self, moment: datetime) -> bool:
        local = moment.astimezone(timezone(self.offset))
        now, day = local.time(), local.weekday()
        if self.start <= self.end:
            return day in self.days and self.start <= now < self.end
        if now >= self.start:
            return day in self.days
        return now < self.end and (day - 1) % 7 in self.days


@dataclass
class Scope:
    """An allowlist (with optional denylist) of hostnames and IP/CIDR targets."""

    allow_hosts: set[str] = field(default_factory=set)
    allow_nets: list[Network] = field(default_factory=list)
    deny_hosts: set[str] = field(default_factory=set)
    deny_nets: list[Network] = field(default_factory=list)
    # `*.example.com` entries, stored as "example.com".
    allow_wildcards: set[str] = field(default_factory=set)
    deny_wildcards: set[str] = field(default_factory=set)
    # The terms of the authorisation (`@` directives).
    engagement: str | None = None
    expires: datetime | None = None  # first moment it no longer holds
    windows: list[TimeWindow] = field(default_factory=list)
    activity: Activity = Activity.SCAN  # the most a plugin may do (@activity)
    # Where the scope came from, and the SHA-256 of its exact bytes: recorded with
    # every run, so that "which scope authorised this?" has an answer.
    path: str | None = None
    text: str | None = None
    sha256: str | None = None

    def add(self, entry: str) -> None:
        """Add one allow (or deny, if prefixed with '!') entry.

        Raises :class:`ScopeError` for anything that is neither a valid IP/CIDR nor a
        valid hostname. A safety config we cannot read must stop the scan, not be
        guessed at (fail closed).
        """
        raw = entry
        entry = entry.split("#", 1)[0].strip()  # drop comments, incl. trailing ones
        if not entry:
            return
        if entry.startswith("@"):
            self._directive(entry)
            return
        deny = entry.startswith("!")
        if deny:
            entry = entry[1:].strip()
        net = _parse_net(entry)
        if net is not None:
            (self.deny_nets if deny else self.allow_nets).append(net)
        elif entry.startswith("*.") and _is_hostname(entry[2:]) and "." in entry[2:]:
            (self.deny_wildcards if deny else self.allow_wildcards).add(entry[2:].lower())
        elif _is_hostname(entry):
            (self.deny_hosts if deny else self.allow_hosts).add(entry.lower())
        else:
            raise ScopeError(f"invalid scope entry {raw.strip()!r}")

    def _directive(self, line: str) -> None:
        name, _, value = line[1:].partition(" ")
        name, value = name.lower(), value.strip()
        if name == "engagement":
            if not value:
                raise ScopeError("@engagement needs a reference, e.g. a contract number")
            self.engagement = value
        elif name == "expires":
            self.expires = _parse_expiry(value)
        elif name == "window":
            self.windows.append(_parse_window(value))
        elif name == "activity":
            self.activity = Activity.parse(value)
        else:
            raise ScopeError(
                f"unknown directive @{name} (known: @engagement, @expires, @window, @activity)"
            )

    def check_activity(self, plugins: list[tuple[str, Activity]]) -> None:
        """Refuse plugins that would go further than the authorisation allows."""
        beyond = [(name, act) for name, act in plugins if act > self.activity]
        if beyond:
            names = ", ".join(f"{name} ({act})" for name, act in beyond)
            source = f" in {self.path}" if self.path else ""
            verb = "goes" if len(beyond) == 1 else "go"
            raise ScopeError(
                f"{names} {verb} beyond what the authorisation{source} allows "
                f"(@activity {self.activity}). If the rules of engagement cover it, add "
                f"'@activity {max(act for _, act in beyond)}' to the scope file."
            )

    def check_time(self, moment: datetime) -> None:
        """Refuse a scan at `moment` if the authorisation has expired or is not open."""
        source = f" in {self.path}" if self.path else ""
        if self.expires is not None and moment >= self.expires:
            raise ScopeError(
                f"The authorisation{source} expired on {self.expires.isoformat()}: no scan "
                "may start after it. Renew the authorisation, then update @expires."
            )
        if self.windows and not any(w.allows(moment) for w in self.windows):
            allowed = "; ".join(w.text for w in self.windows)
            raise ScopeError(
                f"Scanning is only authorised{source} during: {allowed} "
                f"(now: {moment.isoformat(timespec='minutes')})."
            )

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        """Load a scope from an allowlist file (one entry per line)."""
        return cls.from_text(Path(path).read_bytes().decode("utf-8"), str(path))

    @classmethod
    def from_text(cls, text: str, source: str) -> Scope:
        """Read a scope from the text of a scope file; `source` names it in messages and
        in the run's record (a path, or a scope edited in the dashboard)."""
        scope = cls()
        scope.path = source
        scope.sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        scope.text = text
        for lineno, line in enumerate(text.splitlines(), start=1):
            try:
                scope.add(line)
            except ScopeError as exc:
                raise ScopeError(f"{source}:{lineno}: {exc}") from None
        return scope

    @classmethod
    def from_entries(cls, entries: list[str]) -> Scope:
        """Build a scope from an in-memory list of entries (handy for tests)."""
        scope = cls()
        for entry in entries:
            scope.add(entry)
        return scope

    def plan(
        self, target: str, resolver: Resolver | None = None, *, ipv4_only: bool = False
    ) -> ScanTarget:
        """Turn a requested target into the exact addresses that may be scanned.

        This is the gate every scan goes through. It raises :class:`ScopeError` if
        the target is not authorised, or :class:`ResolutionError` if a name cannot
        be resolved.

        * IP / CIDR: must lie inside the allowlist. Denied addresses inside it are
          returned in `exclude`; a target that is denied entirely is refused.
        * Hostname: the name must be allowlisted, and so must **every** address it
          resolves to, IPv4 and IPv6 (unless `ipv4_only`). An allowlisted name is not
          proof that the machine behind it is ours (it may point at a CDN, or have
          been repointed). The name is resolved here, once, and the scan uses these
          addresses, so it cannot change between the check and the scan.
        """
        target = target.strip()
        net = _parse_net(target)
        if net is not None:
            if ipv4_only and net.version == 6:
                raise ScopeError(f"Target {target!r} is IPv6, but the scan is IPv4 only.")
            return self._plan_network(target, net)
        if resolver is None:
            resolver = resolve_ipv4 if ipv4_only else resolve_addresses
        return self._plan_hostname(target, resolver)

    def _plan_network(self, target: str, net: Network) -> ScanTarget:
        if not any(_contained(net, a) for a in self.allow_nets):
            raise ScopeError(_outside(target))
        if net.version == 6 and net.num_addresses > MAX_IPV6_ADDRESSES:
            raise ScopeError(
                f"Target {target!r} has 2^{net.max_prefixlen - net.prefixlen} addresses: too "
                f"many to sweep (at most a /{128 - 16} for IPv6). Scan the hosts by name or "
                "address instead; IPv6 hosts are found through DNS, not by sweeping."
            )
        # Two CIDR blocks overlap only if one contains the other, so each denied
        # block is either all of the target or a part of it.
        denied = [d for d in self.deny_nets if _overlaps(net, d)]
        parts: list[Network] = [d for d in denied if _contained(d, net)]
        # Merge adjacent/nested parts, so their sizes can be added up.
        exclude: list[Network] = list(ipaddress.collapse_addresses(parts))  # type: ignore[type-var]
        covered_by_one = any(_contained(net, d) for d in denied)
        covered_in_parts = sum(d.num_addresses for d in exclude) >= net.num_addresses
        if covered_by_one or covered_in_parts:
            raise ScopeError(f"Target {target!r} is entirely covered by the denylist.")
        return ScanTarget(
            requested=target,
            addresses=(_net_str(net),),
            exclude=tuple(_net_str(d) for d in exclude),
        )

    def name_allowed(self, name: str) -> bool:
        """Is the *name* authorised (exact entry or wildcard), and not denied?"""
        name = name.strip().lower().rstrip(".")

        def under(suffixes: set[str]) -> bool:
            return any(name.endswith("." + s) for s in suffixes)

        if name in self.deny_hosts or under(self.deny_wildcards):
            return False
        return name in self.allow_hosts or under(self.allow_wildcards)

    def allows_discovery(self, domain: str) -> bool:
        """May names under `domain` be looked for? Only with a wildcard covering them."""
        domain = domain.strip().lower().rstrip(".")
        return any(domain == w or domain.endswith("." + w) for w in self.allow_wildcards)

    def plan_discovered(
        self,
        domain: str,
        names: list[str],
        resolver: Resolver | None = None,
        *,
        ipv4_only: bool = False,
        workers: int = 16,
        wildcard_probe: str | None = None,
    ) -> tuple[ScanTarget, list[tuple[str, str]]]:
        """Plan a scan of `domain` and the names found under it.

        Each name is planned like any requested name (resolved once, every address in
        the allowlist); names that fail are returned with the reason and not scanned.
        Names are resolved in parallel (`workers`): discovery can return thousands.

        Wildcard DNS: if a random name under `domain` resolves, the zone answers every
        name, and a discovered name that resolves only to those same addresses tells
        nothing (sources are full of such junk). It is skipped, as `subfinder -nW` would.
        Raises :class:`ScopeError` if none of them may be scanned.
        """
        if resolver is None:
            resolver = resolve_ipv4 if ipv4_only else resolve_addresses
        domain = domain.lower()
        candidates = list(dict.fromkeys([domain, *(n.lower() for n in names)]))
        probe = wildcard_probe or f"zues-wildcard-{secrets.token_hex(6)}"
        try:
            wildcard = frozenset(resolver(f"{probe}.{domain}"))
        except ResolutionError:
            wildcard = frozenset()

        def plan_one(name: str) -> ScanTarget | str:
            try:
                planned = self._plan_hostname(name, resolver)
            except (ScopeError, ResolutionError) as exc:
                return str(exc)
            if name != domain and wildcard and set(planned.addresses) <= wildcard:
                return (
                    f"resolves like any name under {domain} (wildcard DNS record): "
                    "probably not a real host"
                )
            return planned

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            outcomes = list(pool.map(plan_one, candidates))  # order kept
        pairs: list[tuple[str, str]] = []
        skipped: list[tuple[str, str]] = []
        for name, outcome in zip(candidates, outcomes, strict=True):
            if isinstance(outcome, str):
                skipped.append((name, outcome))
            else:
                pairs += [(name, address) for address in outcome.addresses]
        if not pairs:
            raise ScopeError(
                f"none of the {len(candidates)} name(s) found for {domain!r} may be scanned"
            )
        addresses = tuple(dict.fromkeys(ip for _, ip in pairs))
        plan = ScanTarget(requested=domain, addresses=addresses, names=tuple(pairs))
        return plan, skipped

    def _plan_hostname(self, target: str, resolver: Resolver) -> ScanTarget:
        name = target.lower()
        if not self.name_allowed(name):
            raise ScopeError(_outside(target))
        addresses = tuple(dict.fromkeys(resolver(name)))  # de-duplicated, order kept
        if not addresses:
            raise ResolutionError(f"{target!r} did not resolve to any address")
        for address in addresses:
            if not self.is_allowed(address):
                raise ScopeError(
                    f"Target {target!r} resolves to {address}, which is outside the "
                    f"authorised scope. A name in the allowlist does not authorise the "
                    f"address behind it: add the address only if you may scan it."
                )
        return ScanTarget(requested=target, addresses=addresses, hostname=name)

    def is_allowed(self, target: str) -> bool:
        """True iff `target` is wholly inside the allowlist and touches no deny entry.

        A pure check on the text of `target`: no DNS. For an address it is the full
        answer (the orchestrator uses it to re-check every host a scan returns). For
        a hostname it only says the *name* is allowlisted; :meth:`plan` is what
        decides whether a name may be scanned.

        A range is "allowed" here only if none of its addresses is denied:
        `10.0.0.0/24` with `!10.0.0.1` is False, although :meth:`plan` can still
        scan it with the denied address excluded.
        """
        target = target.strip().lower()
        net = _parse_net(target)
        if net is not None:
            if any(_overlaps(net, d) for d in self.deny_nets):
                return False
            return any(_contained(net, a) for a in self.allow_nets)
        return self.name_allowed(target)


def _offset(text: str | None) -> timedelta:
    """ "+07:00", "-05:30", "UTC" or nothing (UTC) -> a UTC offset."""
    if not text or text.upper() in ("UTC", "Z"):
        return timedelta(0)
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", text)
    if match is None:
        raise ScopeError(f"invalid UTC offset {text!r}: write it like +07:00")
    sign = 1 if match.group(1) == "+" else -1
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 14 or minutes > 59:
        raise ScopeError(f"invalid UTC offset {text!r}")
    return sign * timedelta(hours=hours, minutes=minutes)


def _parse_expiry(value: str) -> datetime:
    """ "2026-12-31 +07:00": valid through that whole day; returns the first moment after."""
    parts = value.split()
    if not parts or len(parts) > 2:
        raise ScopeError("@expires needs a date, e.g. @expires 2026-12-31 +07:00")
    try:
        day = date.fromisoformat(parts[0])
    except ValueError:
        raise ScopeError(f"@expires: {parts[0]!r} is not a date (YYYY-MM-DD)") from None
    offset = _offset(parts[1] if len(parts) > 1 else None)
    return datetime.combine(day + timedelta(days=1), time(), tzinfo=timezone(offset))


def _parse_window(value: str) -> TimeWindow:
    """ "[Mon-Fri|Sat,Sun|daily] HH:MM-HH:MM [+07:00]"."""
    parts = value.split()
    days = frozenset(range(7))
    if parts and not re.match(r"\d", parts[0]):
        days = _parse_days(parts.pop(0))
    if not parts or len(parts) > 2:
        raise ScopeError(f"@window {value!r}: write it like @window Mon-Fri 22:00-06:00 +07:00")
    match = re.fullmatch(r"(\d{2}):(\d{2})-(\d{2}):(\d{2})", parts[0])
    if match is None:
        raise ScopeError(f"@window {value!r}: the hours must look like 22:00-06:00")
    h1, m1, h2, m2 = (int(g) for g in match.groups())
    if h1 > 23 or h2 > 24 or m1 > 59 or m2 > 59 or (h2 == 24 and m2):
        raise ScopeError(f"@window {value!r}: not a time of day")
    start = time(h1, m1)
    # "until 24:00" is the end of the day, not its start.
    end = time(23, 59, 59, 999999) if h2 == 24 else time(h2, m2)
    if start == end:
        raise ScopeError(f"@window {value!r}: start and end are the same")
    offset = _offset(parts[1] if len(parts) > 1 else None)
    return TimeWindow(days=days, start=start, end=end, offset=offset, text=value)


def _parse_days(text: str) -> frozenset[int]:
    if text.lower() == "daily":
        return frozenset(range(7))
    days: set[int] = set()
    for item in text.lower().split(","):
        first, _, last = item.partition("-")
        if first not in _DAYS or (last and last not in _DAYS):
            raise ScopeError(f"@window: {text!r} is not a list of days (e.g. Mon-Fri, Sat,Sun)")
        a, b = _DAYS.index(first), _DAYS.index(last or first)
        days.update(range(a, b + 1) if a <= b else [*range(a, 7), *range(0, b + 1)])
    return frozenset(days)


def _outside(target: str) -> str:
    return (
        f"Target {target!r} is outside the authorised scope. "
        f"Add it to the allowlist only if you are permitted to scan it."
    )


def _net_str(net: Network) -> str:
    """A network the way nmap expects it: a bare IP for one address, else CIDR."""
    return str(net.network_address) if net.num_addresses == 1 else str(net)
