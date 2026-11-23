"""Command-line entry point.

`reconkit scan <target> --scope <file>` wires the pieces together: load scope ->
build orchestrator with the nmap plugin -> run -> persist to SQLite -> print a summary.
`reconkit raw <run id>` gives back the scanner's own output kept for a run.
`reconkit runs` lists the stored runs; `reconkit report` turns one into a report.
`reconkit profiles` shows the scan profiles (`scan --profile`).
`reconkit cve sync|status|show` keeps a local copy of NVD to match CVEs against.
`reconkit audit` shows (and `--verify` checks) the audit trail; `reconkit delete`
removes a run, on the record.
`reconkit inventory`, `findings`, `finding` show the state across runs (D1) and record
decisions (fix claimed, risk accepted); `reconkit diff` compares two runs.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from reconkit import __version__, doctor, logs, priority
from reconkit import backup as backups
from reconkit.audit import default_operator
from reconkit.cve.cache import (
    CacheError,
    CveCache,
    refresh_debian,
    refresh_epss,
    refresh_kev,
    sync,
)
from reconkit.cve.feeds import FeedError
from reconkit.cve.nvd import API_KEY_ENV, NvdClient, NvdError
from reconkit.diff import diff_runs
from reconkit.inventory import ACTIVE, Status
from reconkit.inventory_store import FindingEvent, InventoryError
from reconkit.orchestrator import DISCOVER_LIMIT, RunStatus, ScanRun
from reconkit.profiles import DEFAULT_PROFILE, ProfileError, ScanProfile, load_profiles
from reconkit.report import render_html, stored_model
from reconkit.report.sarif import to_sarif
from reconkit.scanning import ScanSpec, execute, indent
from reconkit.schema import Asset, Finding
from reconkit.storage import Storage, StorageError

log = logging.getLogger(__name__)

# Findings printed per host after a scan, most urgent first; the rest are counted.
MAX_FINDINGS_SHOWN = 10


def _print_summary(run: ScanRun, run_id: int, db_path: str) -> None:
    services = [s for a in run.assets for s in a.services]
    findings = [f for a in run.assets for f in a.findings]
    print(f"\nScan run #{run_id}  target={run.target}  status={run.status}  (saved to {db_path})")
    tools = ", ".join(
        f"{name} {version or '(unknown version)'}" for name, version in run.tool_versions.items()
    )
    print(f"  scanners: {tools}")
    if run.scope_sha256:
        engagement = f", engagement {run.engagement!r}" if run.engagement else ""
        print(
            f"  authorised by: {run.scope_path} (sha256 {run.scope_sha256[:12]}...)"
            f"{engagement}; operator {run.operator}"
        )
    if run.profile:
        print(f"  profile: {run.profile} ({_profile_line(run)})")
    plan = run.plan
    if plan is not None and plan.hostname:
        print(f"  resolved: {plan.hostname} -> {', '.join(plan.addresses)}")
    if plan is not None and plan.exclude:
        print(f"  excluded (denylist): {', '.join(plan.exclude)}")
    print(f"  hosts: {_hosts_summary(run)}   services: {len(services)}   findings: {len(findings)}")
    for asset in run.assets:
        label = asset.host if asset.ip in (None, asset.host) else f"{asset.host} ({asset.ip})"
        print(f"\n  {label}")
        if len(asset.names) > 1:
            print(f"    names: {', '.join(asset.names)}")
        if asset.route:
            print(f"    route: {_route_line(asset)}")
        if not asset.services:
            print("    no open ports found")
            continue
        print(f"    {'PORT':<11}{'SERVICE':<16}{'PRODUCT / VERSION'}")
        print(f"    {'-' * 10} {'-' * 15} {'-' * 20}")
        for s in asset.services:
            pv = " ".join(p for p in (s.product, s.version) if p) or "-"
            print(f"    {f'{s.port}/{s.protocol}':<11}{(s.name or '-'):<16}{pv}")
        # Most urgent first: known-exploited, then likely-exploited, then impact.
        ranked = sorted(asset.findings, key=priority.sort_key)
        for f in ranked[:MAX_FINDINGS_SHOWN]:
            sure = f", {f.confidence}" if f.confidence else ""
            print(
                f"    {priority.priority(f)} [{f.severity.upper()}{sure}] {f.title}"
                + (f" ({f.cve})" if f.cve else "")
            )
            print(f"        priority: {_risk_line(f)}")
            if f.evidence:
                print(f"        evidence: {f.evidence}")
        if len(ranked) > MAX_FINDINGS_SHOWN:
            print(
                f"    ... and {len(ranked) - MAX_FINDINGS_SHOWN} less urgent finding(s): "
                f"reconkit findings --db {db_path}, or the HTML report"
            )
    several = len(run.raw_outputs) > 1
    for i, o in enumerate(run.raw_outputs, start=1):
        pick = f" --index {i}" if several else ""
        print(
            f"\n  raw output kept: {o.plugin} ({o.format}, {o.size} bytes, "
            f"sha256 {o.sha256[:12]}...)  ->  reconkit raw {run_id}{pick} --db {db_path}"
        )


def _risk_line(f: Finding) -> str:
    """Why this priority, plus the facts behind it: CVSS, CWE, KEV, EPSS."""
    parts = [priority.reason(f)]
    if f.cvss_score is not None and "CVSS" not in parts[0]:
        parts.append(f"CVSS {f.cvss_score:.1f}")
    if f.epss is not None and "EPSS" not in parts[0]:
        parts.append(f"EPSS {f.epss:.1%}")
    if f.cwe:
        parts.append(", ".join(f.cwe))
    return " | ".join(parts)


def _profile_line(run: ScanRun) -> str:
    try:
        return ScanProfile(**(run.profile_settings or {})).summary()
    except (TypeError, ProfileError):
        return "settings unreadable"


def _route_line(asset: Asset) -> str:
    """The path to a host, e.g. "192.168.1.1 -> ? -> 10.0.0.5 (3 hops)".

    A "?" stands for routers that never answered (a gap in the TTLs).
    """
    parts: list[str] = []
    expected = 1
    for hop in asset.route:
        if hop.ttl > expected:
            parts.append("?")
        parts.append(hop.ip or "?")
        expected = hop.ttl + 1
    return f"{' -> '.join(parts)} ({asset.route[-1].ttl} hops)"


def _hosts_summary(run: ScanRun) -> str:
    """Hosts that responded; for a range target, out of how many addresses scanned."""
    found = len(run.assets)
    plan = run.plan
    if plan is None or plan.hostname:
        return str(found)  # a name: no range to compare against
    size = sum(_size(a) for a in plan.addresses) - sum(_size(e) for e in plan.exclude)
    # The silent addresses are not listed: they may be unused, down, or filtered.
    return f"{found} responded of {size} addresses" if size > 1 else str(found)


def _size(network: str) -> int:
    return ipaddress.ip_network(network, strict=False).num_addresses


def _spec(args: argparse.Namespace) -> ScanSpec:
    """The scan the command line asks for."""
    return ScanSpec(
        target=args.target,
        scope=args.scope,
        db=args.db,
        profile=args.profile,
        config=args.config,
        overrides={
            "ports": args.ports,
            "top_ports": args.top_ports,
            "timing": args.timing,
            "max_rate": args.max_rate,
            "check_rate": args.check_rate,
            "host_timeout": args.host_timeout,
            "timeout": args.timeout,
            "traceroute": args.traceroute,
            "assume_up": True if args.assume_up else None,
        },
        no_cve=args.no_cve,
        cve_db=args.cve_db,
        cve_cache=args.cve_cache,
        credentials=args.credentials,
        nuclei=args.nuclei,
        nuclei_templates=args.nuclei_templates,
        discover=args.discover,
        subfinder_config=args.subfinder_config,
        discover_limit=args.discover_limit,
        ipv4_only=args.ipv4_only,
        operator=args.operator,
        engagement=args.engagement,
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    outcome = execute(_spec(args))
    for message in outcome.messages:
        print(message, file=sys.stderr)
    if outcome.code == 0 and outcome.run is not None and outcome.run_id is not None:
        _print_summary(outcome.run, outcome.run_id, args.db)
        _print_changes(outcome.changes)
    return outcome.code


DEFAULT_CVE_CACHE = "reconkit-cve.db"

# A CPE 2.3 prefix naming at least a vendor and a product.
_CPE_PREFIX = re.compile(r"cpe:2\.3:[aoh]:[^:\s*]+:[^:\s*]+(?::[^:\s]+)*")


def _cmd_cve_sync(args: argparse.Namespace) -> int:
    """Download or update the local NVD cache."""
    products: list[str | None] = list(args.product or [None])
    for product in products:
        if product is not None and not _CPE_PREFIX.fullmatch(product):
            print(
                "error: --product must be a CPE 2.3 prefix such as "
                f"cpe:2.3:a:openbsd:openssh, not {product!r}",
                file=sys.stderr,
            )
            return 2
    api_key = os.environ.get(API_KEY_ENV) or None
    client = NvdClient(api_key=api_key)
    if not api_key:
        print(
            f"note: no NVD API key in {API_KEY_ENV}: NVD then allows 5 requests per 30 s, "
            "so a large download is slow",
            file=sys.stderr,
        )

    def progress(done: int, total: int) -> None:
        print(f"  {done}/{total} CVEs", file=sys.stderr)

    try:
        with CveCache(args.cache, create=True) as cache:
            for product in products:
                what = product or "all of NVD"
                print(f"syncing {what} into {args.cache} ...", file=sys.stderr)
                result = sync(cache, client, product=product, full=args.full, progress=progress)
                since = f"changed since {result.since[:19]}" if result.since else "full download"
                print(
                    f"{what}: {result.changed} CVE(s) stored, {result.removed} rejected "
                    f"removed ({since})"
                )
            # Exploitation signals, for ranking findings (G11): one file each.
            if not args.no_kev:
                version, count = refresh_kev(cache)
                print(f"CISA KEV catalog {version}: {count} known exploited CVEs")
            if not args.no_epss:
                date, count = refresh_epss(cache)
                print(f"FIRST EPSS scores of {(date or '?')[:10]}: {count} CVEs")
            if args.debian:
                count = refresh_debian(cache, set(args.debian))
                print(f"Debian security tracker ({', '.join(args.debian)}): {count} entries")
    except CacheError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (NvdError, FeedError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("what was downloaded so far is kept; run the same command again", file=sys.stderr)
        return 1
    return 0


def _cmd_cve_status(args: argparse.Namespace) -> int:
    try:
        with CveCache(args.cache) as cache:
            status = cache.status()
            feeds = cache.feeds()
    except CacheError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{args.cache}: {status.cves} CVEs, {status.ranges} affected product ranges")
    for scope, synced in status.scopes.items():
        print(f"  {scope}: synced {synced[:19]}")
    for feed, (fetched, version, rows) in feeds.items():
        print(f"  {feed}: {rows} entries ({version or '?'}), downloaded {fetched[:19]}")
    return 0


def _cmd_cve_show(args: argparse.Namespace) -> int:
    try:
        with CveCache(args.cache) as cache:
            details = cache.details(args.cve_id.upper())
    except CacheError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if details is None:
        print(f"error: {args.cve_id} is not in {args.cache}", file=sys.stderr)
        return 1
    affects = details.pop("affects")
    for key, value in details.items():
        if value not in (None, ""):
            print(f"{key:>14}: {value}")
    for a in affects:
        bounds = ", ".join(
            f"{op} {a[k]}"
            for k, op in (
                ("start_incl", ">="),
                ("start_excl", ">"),
                ("end_incl", "<="),
                ("end_excl", "<"),
            )
            if a[k]
        )
        exact = (a["version"] or "") + (a["update"] or "")
        print(f"{'affects':>14}: {a['vendor']}:{a['product']} {exact}{bounds}")
    return 0


def _cmd_profiles(args: argparse.Namespace) -> int:
    """List the built-in profiles and those of the config file."""
    try:
        profiles = load_profiles(args.config)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for profile in profiles.values():
        default = "  (default)" if profile.name == DEFAULT_PROFILE else ""
        print(f"{profile.name}{default}")
        if profile.description:
            print(f"    {profile.description}")
        print(f"    {profile.summary()}")
        print(f"    nmap {' '.join(profile.nmap_args())}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    """Print the audit trail, verify it, or show a recorded scope file."""
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            if args.scope:
                text = store.scope_snapshot(args.scope)
                if text is None:
                    print(f"error: no single scope recorded as {args.scope}", file=sys.stderr)
                    return 1
                # Bytes: the console's newline translation must not alter the record.
                sys.stdout.flush()
                sys.stdout.buffer.write(text.encode("utf-8"))
                sys.stdout.buffer.flush()
                return 0
            events = store.audit_events()
            report = store.verify_audit() if args.verify else None
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for event_id, event, _hash in events:
        detail = event.detail
        what = {
            "scan": f"run #{detail.get('run_id')} {detail.get('status')}",
            "refused": f"refused: {detail.get('reason', '')}",
            "deleted": f"deleted run #{detail.get('run_id')}",
        }.get(event.kind, event.kind)
        scope = f" scope {event.scope_sha256[:12]}" if event.scope_sha256 else ""
        engagement = f" [{event.engagement}]" if event.engagement else ""
        print(
            f"#{event_id:<4} {event.at[:19]}  {event.operator or '?'}{engagement}  "
            f"{event.target}: {what}{scope}"
        )
    if report is None:
        return 0
    print(f"\n{report.events} event(s); head of the chain: {report.head}")
    if report.intact:
        print("chain intact; every scan's evidence matches what was recorded")
        print("keep the head hash outside this database to detect a rewritten history")
        return 0
    for problem in report.problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    """What this machine can scan with, and what to install or fix."""
    checks = doctor.gather(config=args.config, cve_cache=args.cve_cache)
    if args.json:
        print(json.dumps(doctor.as_json(checks), indent=2, ensure_ascii=False))
    else:
        print(doctor.header())
        print()
        print(doctor.render(checks))
    return 1 if any(c.blocking for c in checks) else 0


def _cmd_backup(args: argparse.Namespace) -> int:
    """Back up the database, or check a backup before restoring it."""
    try:
        if args.verify:
            check = backups.verify(args.verify)
            removed: list[str] = []
        else:
            made = backups.backup(args.db, args.out_dir, keep=args.keep)
            check, removed = made.check, made.removed
    except backups.BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2 if "not found" in str(exc) or "--keep" in str(exc) else 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    size = f"{check.size / 1024:.0f} KiB"
    what = "backup checked" if args.verify else "backup written"
    print(f"{what}: {check.path} ({size}, {check.runs} run(s), schema v{check.schema_version})")
    print(f"sha256: {check.sha256}")
    if check.audit_head is not None:
        print(f"audit trail: {check.audit_events} event(s), head {check.audit_head}")
        if not args.verify:
            print("  keep that head hash somewhere else: it proves this history later")
    else:
        print("audit trail: not checked (the backup has another schema version)")
    for name in removed:
        print(f"removed old backup: {name}")
    for problem in check.problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return 0 if check.ok else 1


def _cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        print(
            f"error: deleting run #{args.run_id} cannot be undone; add --yes to confirm",
            file=sys.stderr,
        )
        return 2
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            deleted = store.delete_run(args.run_id, operator=args.operator or default_operator())
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not deleted:
        print(f"error: no run #{args.run_id} in {args.db}", file=sys.stderr)
        return 1
    print(f"run #{args.run_id} deleted; the deletion is recorded in the audit trail")
    return 0


_CHANGE_LABEL = {
    "fake_fix": "FAKE FIX: claimed fixed, still there",
    "reappeared": "reappeared",
    "new": "new",
    "verified_fixed": "verified fixed",
    "gone": "gone without a fix claim (fixed? or changed?)",
    "acceptance_expired": "risk acceptance expired",
    "seen_again": "still open",
}


def _print_changes(changes: list[FindingEvent]) -> None:
    """What this run changed in the inventory, most alarming first."""
    if not changes:
        return
    counts = Counter(e.event for e in changes)
    summary = ", ".join(f"{counts[k]} {_CHANGE_LABEL[k]}" for k in _CHANGE_LABEL if counts[k])
    print(f"\n  inventory: {summary}")
    for e in changes:
        if e.event in ("fake_fix", "reappeared", "verified_fixed", "acceptance_expired"):
            alert = "ALERT " if e.event in ("fake_fix", "reappeared") else ""
            label = _CHANGE_LABEL[e.event]
            print(f"    {alert}{label}: finding #{e.finding_id} {e.title} on {e.host}")


def _cmd_inventory(args: argparse.Namespace) -> int:
    """Every host and service seen across runs, or rebuild the inventory."""
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            if args.rebuild:
                count = store.rebuild_inventory()
                print(f"inventory rebuilt from {count} run(s)")
                return 0
            hosts = store.inventory_hosts()
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not hosts:
        print("the inventory is empty: no scan has been saved yet")
    for h in hosts:
        label = h["host"] if h["ip"] in (None, h["host"]) else f"{h['host']} ({h['ip']})"
        state = "up" if h["state"] == "up" else f"NOT RESPONDING since {h['state_since'][:10]}"
        print(f"{label}  [{state}]  first seen {h['first_seen'][:10]}, last {h['last_seen'][:10]}")
        for s in h["services"]:
            what = " ".join(p for p in (s["product"], s["version"]) if p) or "-"
            closed = "" if s["state"] == "open" else "  (closed)"
            print(
                f"    {s['port']}/{s['protocol']:<4} {s['name'] or '?':<14} {what}{closed}"
                f"  since {s['first_seen'][:10]}"
            )
    return 0


def _cmd_findings(args: argparse.Namespace) -> int:
    """Findings across runs, by status; the active ones by default."""
    if not _db_exists(args.db):
        return 2
    statuses = None if args.all else set(args.status or [str(s) for s in ACTIVE])
    try:
        with Storage(args.db) as store:
            rows = store.inventory_findings(statuses)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not rows:
        print("no finding with that status")
        return 0
    rows.sort(key=lambda r: priority.sort_key(r.as_finding()))
    print(f"{'ID':>4}  {'STATUS':<11} {'PRIO':<4} {'SEVERITY':<8}  {'HOST':<22} {'PORT':<9} ISSUE")
    for r in rows:
        port = f"{r.port}/{r.protocol}" if r.port else "-"
        issue = f"{r.cve} {r.title}" if r.cve else r.title
        print(
            f"{r.id:>4}  {r.status:<11} {priority.priority(r.as_finding()):<4} "
            f"{r.severity:<8}  {(r.ip or r.host):<22} {port:<9} {issue}"
        )
    return 0


def _cmd_finding(args: argparse.Namespace) -> int:
    """One finding's state and history, or a decision about it."""
    if not _db_exists(args.db):
        return 2
    action = (
        "claim_fixed"
        if args.claim_fixed
        else "accept"
        if args.accept
        else "reopen"
        if args.reopen
        else None
    )
    try:
        with Storage(args.db) as store:
            if action is not None:
                new = store.decide_finding(
                    args.finding_id,
                    action,
                    actor=args.operator or default_operator(),
                    note=args.reason,
                    until=args.until,
                )
                print(f"finding #{args.finding_id} is now {new} (recorded in the audit trail)")
                if new == Status.FIX_CLAIMED:
                    print("the next scan that looks at it will verify the fix (or flag a fake fix)")
                return 0
            row = store.inventory_finding(args.finding_id)
            history = store.finding_history(args.finding_id)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if row is None:
        print(f"error: no finding #{args.finding_id} in the inventory", file=sys.stderr)
        return 1
    print(f"#{row.id} {row.cve or row.rule_id or ''} {row.title}")
    print(f"  host: {row.host}" + (f" ({row.ip})" if row.ip and row.ip != row.host else ""))
    if row.port:
        print(f"  port: {row.port}/{row.protocol}")
    print(f"  status: {row.status} since {row.status_since[:19]}")
    if row.confidence:
        print(f"  confidence: {row.confidence}")
    if row.accepted_until:
        print(f"  accepted until: {row.accepted_until}")
    print(
        f"  priority: {priority.priority(row.as_finding())} ({priority.reason(row.as_finding())})"
    )
    print(f"  seen: first {row.first_seen[:19]}, last {row.last_seen[:19]}")
    print(f"  fingerprint: {row.fingerprint}")
    print("  history:")
    for e in history:
        who = f" by {e.actor}" if e.actor else f" (run #{e.run_id})" if e.run_id else ""
        note = f": {e.note}" if e.note else ""
        print(f"    {e.at[:19]}  {e.old_status or '-'} -> {e.new_status}  [{e.event}]{who}{note}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """What changed between two runs (default: the latest run and the one before it)."""
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            if args.before is None or args.after is None:
                pair = _latest_pair(store, args.before)
                if pair is None:
                    print("error: need two runs of the same target to compare", file=sys.stderr)
                    return 2
                before_id, after_id = pair
            else:
                before_id, after_id = args.before, args.after
            before, after = store.load_run(before_id), store.load_run(after_id)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if before is None or after is None:
        missing = before_id if before is None else after_id
        print(f"error: no run #{missing} in {args.db}", file=sys.stderr)
        return 2
    result = diff_runs(before, after)
    print(
        f"run #{before_id} ({before.started_at[:16]}) -> run #{after_id} ({after.started_at[:16]})"
    )
    for caveat in result.caveats:
        print(f"  caution: {caveat}")
    if result.empty:
        print("  no change")
        return 0
    for host in result.hosts_added:
        print(f"  + host {host}")
    for host in result.hosts_removed:
        print(f"  - host {host} (did not answer, or no longer exists)")
    for host, s in result.services_added:
        print(
            f"  + {host} {s.port}/{s.protocol} {s.name or '?'} {s.product or ''} {s.version or ''}"
        )
    for host, s in result.services_removed:
        print(f"  - {host} {s.port}/{s.protocol} {s.name or '?'}")
    for c in result.services_changed:
        print(f"  ~ {c.host} {c.port}/{c.protocol}: {c.before} -> {c.after}")
    for host, f in result.findings_added:
        print(f"  + finding on {host}: {f.cve or ''} {f.title}")
    for host, f in result.findings_removed:
        print(f"  - finding on {host}: {f.cve or ''} {f.title}")
    return 0


def _latest_pair(store: Storage, after: int | None) -> tuple[int, int] | None:
    """The newest run (or `after`) and the run of the same target just before it."""
    runs = [r for r in store.list_runs() if r.status != RunStatus.FAILED]
    newest = next((r for r in runs if after is None or r.id == after), None)
    if newest is None:
        return None
    earlier = next((r for r in runs if r.target == newest.target and r.id < newest.id), None)
    return None if earlier is None else (earlier.id, newest.id)


def _server(args: argparse.Namespace) -> Any:
    """The service modules, or None (and a message) without `reconkit[server]`."""
    try:
        from reconkit.server import config, queue, scheduler
    except ImportError as exc:
        print(
            f"error: this command needs the server extra: pip install 'reconkit[server]' ({exc})",
            file=sys.stderr,
        )
        return None
    try:
        return config.load_config(args.config), queue, scheduler
    except config.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def _cmd_token(args: argparse.Namespace) -> int:
    """Make an API token; print it once, and the line that goes in service.toml."""
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"token for {args.name} (shown once, keep it secret): {token}")
    print("\nadd to service.toml:\n")
    print(f'[[tokens]]\nname = "{args.name}"\nsha256 = "{digest}"\nrole = "{args.role}"')
    return 0


def _cmd_enqueue(args: argparse.Namespace) -> int:
    loaded = _server(args)
    if loaded is None:
        return 2
    config, queue, _ = loaded
    try:
        job = queue.enqueue_scan(
            queue.queue(config), config, args.target, args.operator or default_operator()
        )
    except queue.UNREACHABLE as exc:
        print(
            f"error: cannot reach Redis at {queue.safe_url(config.redis_url)}: {exc}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001 - an unknown target, a bad profile file, ...
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"scan of {args.target} enqueued as job {job.id}")
    return 0


def _cmd_worker(args: argparse.Namespace) -> int:
    loaded = _server(args)
    if loaded is None:
        return 2
    config, queue, _ = loaded
    where = queue.safe_url(config.redis_url)
    try:
        worker = queue.make_worker(queue.queue(config))
        print(f"worker listening on {where}, queue {config.queue!r}", file=sys.stderr)
        worker.work(burst=args.burst)
    except queue.UNREACHABLE as exc:
        print(f"error: cannot reach Redis at {where}: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_scheduler(args: argparse.Namespace) -> int:
    loaded = _server(args)
    if loaded is None:
        return 2
    config, queue, scheduler = loaded
    q = queue.queue(config)
    if args.once:
        try:
            names = scheduler.tick(config, q)
        except queue.UNREACHABLE as exc:
            where = queue.safe_url(config.redis_url)
            print(f"error: cannot reach Redis at {where}: {exc}", file=sys.stderr)
            return 1
        print(f"enqueued: {', '.join(names) or 'nothing due'}")
        return 0
    scheduled = [t.name for t in config.targets.values() if t.every]
    print(f"scheduler started for: {', '.join(scheduled) or 'no target'}", file=sys.stderr)
    scheduler.run_forever(config, q)
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    """Serve the web API and dashboard until interrupted."""
    try:
        from reconkit.server import web
        from reconkit.server.config import ConfigError
    except ImportError as exc:
        print(
            f"error: this command needs the server extra: pip install 'reconkit[server]' ({exc})",
            file=sys.stderr,
        )
        return 2
    if not _loopback(args.host):
        print(
            f"warning: listening on {args.host}: put a TLS reverse proxy in front, and send "
            "X-Forwarded-Proto from it, so that tokens and cookies never cross the network "
            "in clear text",
            file=sys.stderr,
        )
    try:
        web.serve(args.config, host=args.host, port=args.port)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _db_exists(path: str) -> bool:
    """Reading commands never create a database: say so if there is none."""
    if Path(path).is_file():
        return True
    print(f"error: database not found: {path}", file=sys.stderr)
    return False


def _cmd_runs(args: argparse.Namespace) -> int:
    """List the stored runs, newest first."""
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            runs = store.list_runs(args.limit)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not runs:
        print(f"no run stored in {args.db}")
        return 0
    print(
        f"{'ID':>4}  {'STARTED (UTC)':<19}  {'STATUS':<9}  {'HOSTS':>5}  {'SVCS':>5}  "
        f"{'FINDINGS':>8}  TARGET"
    )
    for r in runs:
        started = r.started_at[:19].replace("T", " ")
        print(
            f"{r.id:>4}  {started:<19}  {r.status:<9}  {r.hosts:>5}  {r.services:>5}  "
            f"{r.findings:>8}  {r.target}"
        )
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Write the report of one run (the latest by default)."""
    if not (args.html or args.json or args.sarif):
        print("error: choose at least one output: --html, --json or --sarif", file=sys.stderr)
        return 2
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            run_id = args.run if args.run is not None else store.latest_run_id()
            if run_id is None:
                print(f"error: no run stored in {args.db}", file=sys.stderr)
                return 2
            model = stored_model(store, run_id)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if model is None:
        print(f"error: no run #{run_id} in {args.db}", file=sys.stderr)
        return 2

    outputs = []
    if args.html:
        outputs.append((args.html, "HTML", render_html(model)))
    if args.json:
        outputs.append((args.json, "JSON", json.dumps(model, indent=2, ensure_ascii=False) + "\n"))
    if args.sarif:
        sarif = json.dumps(to_sarif(model), indent=2, ensure_ascii=False) + "\n"
        outputs.append((args.sarif, "SARIF", sarif))
    for path, kind, text in outputs:
        try:
            Path(path).write_text(text, encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"error: cannot write {path}: {exc}", file=sys.stderr)
            return 1
        about = f"{model['run']['target']}, {model['run']['status']}"
        print(f"{kind} report of run #{run_id} ({about}) written to {path}")
    print(
        "note: the report contains the scan results; share it only with people "
        "authorised to see them.",
        file=sys.stderr,
    )
    return 0


def _cmd_raw(args: argparse.Namespace) -> int:
    """Print (or save) the raw scanner output stored for a run."""
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            if store.load_run(args.run_id) is None:
                print(f"error: no run #{args.run_id} in {args.db}", file=sys.stderr)
                return 2
            outputs = store.outputs_for_run(args.run_id)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    numbered = list(enumerate(outputs, start=1))
    if args.plugin:
        numbered = [(i, o) for i, o in numbered if o.plugin == args.plugin]
    if args.index is not None:
        numbered = [(i, o) for i, o in numbered if i == args.index]
    if not numbered:
        which = f" from {args.plugin}" if args.plugin else ""
        which += f" with index {args.index}" if args.index is not None else ""
        print(f"error: run #{args.run_id} has no raw output{which} stored", file=sys.stderr)
        return 1
    if len(numbered) > 1:
        print(
            f"error: run #{args.run_id} has {len(numbered)} raw outputs; pick one with --index:",
            file=sys.stderr,
        )
        for i, o in numbered:
            print(f"  {i}  {o.plugin:<8} {' '.join(o.command)}", file=sys.stderr)
        return 2

    ((_, output),) = numbered
    # Details go to stderr so that stdout is the tool's output and nothing else.
    print(f"plugin:  {output.plugin} ({output.format})", file=sys.stderr)
    print(f"command: {' '.join(output.command)}", file=sys.stderr)
    print(f"sha256:  {output.sha256}  ({output.size} bytes, verified)", file=sys.stderr)
    if output.stderr:
        print(f"stderr:\n{indent(output.stderr)}", file=sys.stderr)
    data = output.content.encode("utf-8")
    if args.out:
        Path(args.out).write_bytes(data)
        print(f"written to {args.out}", file=sys.stderr)
    else:
        # Bytes, not text: the console's own encoding must not mangle the evidence.
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Logging options work before or after the subcommand: `reconkit -v scan ...` and
    # `reconkit scan ... -v`. SUPPRESS keeps a subcommand from resetting them.
    logging_options = argparse.ArgumentParser(add_help=False)
    logging_options.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="log what happens: -v progress, -vv details (stderr)",
    )
    logging_options.add_argument(
        "--log-file", default=argparse.SUPPRESS, help="also write a full (debug) log to this file"
    )
    logging_options.add_argument(
        "--log-format",
        choices=["text", "json"],
        default=argparse.SUPPRESS,
        help="json: one object per line, for a log collector",
    )
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="Recon orchestrator & vulnerability management (academic project).",
        parents=[logging_options],
    )
    sub = _Subparsers(parser.add_subparsers(dest="command", required=True), logging_options)

    scan = sub.add_parser("scan", help="scan a single target in scope")
    scan.add_argument("target", help="domain, IP, or CIDR to scan")
    scan.add_argument(
        "--scope", required=True, help="path to the allowlist file (one entry per line)"
    )
    scan.add_argument("--db", default="reconkit.db", help="SQLite database path")
    cve_data = scan.add_mutually_exclusive_group()
    cve_data.add_argument("--no-cve", action="store_true", help="skip the CVE matching stage")
    cve_data.add_argument("--cve-db", help="path to a CVE data JSON (default: bundled seed)")
    cve_data.add_argument(
        "--cve-cache", help="match against a local NVD cache (see `reconkit cve sync`)"
    )
    who = scan.add_argument_group("authorisation", "recorded with the run (audit trail)")
    who.add_argument("--operator", help="who runs the scan (default: user@host)")
    who.add_argument(
        "--engagement",
        help="the authorisation this scan belongs to, e.g. a contract number "
        "(default: @engagement in the scope file)",
    )
    tuning = scan.add_argument_group(
        "scan profile", "how to scan; flags override single settings of the profile"
    )
    tuning.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=f"quick | standard | full | gentle, or one from --config (default {DEFAULT_PROFILE})",
    )
    tuning.add_argument("--config", help="TOML file with more profiles ([profiles.<name>])")
    ports = tuning.add_mutually_exclusive_group()
    ports.add_argument("--ports", help="TCP ports, e.g. 22,80,8000-8100; '-' for all")
    ports.add_argument("--top-ports", type=int, help="the N most common ports")
    tuning.add_argument("--timing", type=int, choices=range(6), help="nmap -T0 ... -T5")
    tuning.add_argument("--max-rate", type=int, help="send at most N packets per second")
    tuning.add_argument(
        "--check-rate", type=int, help="active checks (nuclei): at most N requests per second"
    )
    tuning.add_argument("--host-timeout", type=int, help="give up on one host after N seconds")
    tuning.add_argument("--timeout", type=int, help="stop the whole scan after N seconds")
    tuning.add_argument(
        "--traceroute",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="record the network path to each host (for the map; slower)",
    )
    tuning.add_argument(
        "--discover",
        action="store_true",
        help="first find the names under the target domain (subfinder; needs *.domain "
        "in the scope), then scan those in scope",
    )
    tuning.add_argument(
        "--credentials",
        help="TOML file of SSH keys ([[ssh]]): log in to Debian hosts and check their "
        "installed packages against the Debian security tracker",
    )
    tuning.add_argument(
        "--nuclei",
        action="store_true",
        help="also run nuclei templates on the services found (active checks: "
        "only if the authorisation covers them)",
    )
    tuning.add_argument(
        "--nuclei-templates",
        metavar="DIR",
        help="run exactly these nuclei templates, offline (default: "
        "$RECONKIT_NUCLEI_TEMPLATES, else nuclei's own installation)",
    )
    tuning.add_argument(
        "--subfinder-config",
        metavar="FILE",
        help="subfinder provider config with API keys (default: "
        "$RECONKIT_SUBFINDER_CONFIG, else ~/.config/subfinder/provider-config.yaml)",
    )
    tuning.add_argument(
        "--discover-limit",
        type=int,
        metavar="N",
        help=f"consider at most N discovered names (default {DISCOVER_LIMIT})",
    )
    tuning.add_argument(
        "--ipv4-only",
        action="store_true",
        help="look up and scan only the IPv4 addresses of a name (not its AAAA records)",
    )
    tuning.add_argument(
        "--assume-up",
        action="store_true",
        help="scan hosts that ignore ping (nmap -Pn); slow on ranges",
    )
    scan.set_defaults(func=_cmd_scan)

    cve = sub.add_parser("cve", help="keep a local copy of NVD to match CVEs against")
    cve_sub = _Subparsers(cve.add_subparsers(dest="cve_command", required=True), logging_options)
    cve_sync = cve_sub.add_parser(
        "sync",
        help="download CVEs from the NVD API into the cache (only changes after the first time)",
        description=f"An NVD API key, if you have one, is read from the {API_KEY_ENV} "
        "environment variable: it allows ten times faster downloads.",
    )
    cve_sync.add_argument("--cache", default=DEFAULT_CVE_CACHE, help="cache file (SQLite)")
    cve_sync.add_argument(
        "--product",
        action="append",
        help="only CVEs of this product, as a CPE prefix, e.g. cpe:2.3:a:openbsd:openssh "
        "(repeatable; default: all of NVD, a long first download)",
    )
    cve_sync.add_argument("--full", action="store_true", help="download everything again")
    cve_sync.add_argument(
        "--no-kev", action="store_true", help="do not refresh the CISA KEV catalog"
    )
    cve_sync.add_argument("--no-epss", action="store_true", help="do not refresh EPSS scores")
    cve_sync.add_argument(
        "--debian",
        action="append",
        metavar="RELEASE",
        help="also keep the Debian security tracker for this release, e.g. bookworm "
        "(repeatable; for `scan --credentials`)",
    )
    cve_sync.set_defaults(func=_cmd_cve_sync)
    cve_status = cve_sub.add_parser("status", help="what the cache holds and when it was synced")
    cve_status.add_argument("--cache", default=DEFAULT_CVE_CACHE, help="cache file (SQLite)")
    cve_status.set_defaults(func=_cmd_cve_status)
    cve_show = cve_sub.add_parser("show", help="one CVE as stored in the cache")
    cve_show.add_argument("cve_id", help="e.g. CVE-2021-23017")
    cve_show.add_argument("--cache", default=DEFAULT_CVE_CACHE, help="cache file (SQLite)")
    cve_show.set_defaults(func=_cmd_cve_show)

    profiles = sub.add_parser("profiles", help="list the scan profiles")
    profiles.add_argument("--config", help="TOML file with more profiles")
    profiles.set_defaults(func=_cmd_profiles)

    raw = sub.add_parser("raw", help="show the raw scanner output kept for a run")
    raw.add_argument("run_id", type=int, help="id of the run, as printed by `scan`")
    raw.add_argument("--db", default="reconkit.db", help="SQLite database path")
    raw.add_argument("--plugin", help="which scanner's output, if the run has several")
    raw.add_argument(
        "--index", type=int, help="which output, by its number (a dual-stack scan has two)"
    )
    raw.add_argument("--out", help="write the output to this file instead of the screen")
    raw.set_defaults(func=_cmd_raw)

    audit = sub.add_parser("audit", help="the audit trail: who scanned what, when, how")
    audit.add_argument("--db", default="reconkit.db", help="SQLite database path")
    audit.add_argument(
        "--verify", action="store_true", help="check the hash chain and the stored evidence"
    )
    audit.add_argument("--scope", metavar="SHA256", help="print a recorded scope file")
    audit.set_defaults(func=_cmd_audit)

    delete = sub.add_parser("delete", help="delete a stored run (recorded in the audit trail)")
    delete.add_argument("run_id", type=int)
    delete.add_argument("--db", default="reconkit.db", help="SQLite database path")
    delete.add_argument("--yes", action="store_true", help="confirm: the run cannot be restored")
    delete.add_argument("--operator", help="who deletes it (default: user@host)")
    delete.set_defaults(func=_cmd_delete)

    doctor_cmd = sub.add_parser(
        "doctor", help="check the tools, rights and data this machine scans with"
    )
    doctor_cmd.add_argument("--config", help="also check a service.toml, its database and Redis")
    doctor_cmd.add_argument(
        "--cve-cache", default=DEFAULT_CVE_CACHE, help="NVD cache to check (default: %(default)s)"
    )
    doctor_cmd.add_argument("--json", action="store_true", help="machine-readable output")
    doctor_cmd.set_defaults(func=_cmd_doctor)

    backup = sub.add_parser(
        "backup", help="back up the database (safe while scans run), or check a backup"
    )
    backup.add_argument("--db", default="reconkit.db", help="SQLite database path")
    backup.add_argument("--out-dir", default="backups", help="where to write the backup")
    backup.add_argument("--keep", type=int, help="keep only the N newest backups there")
    backup.add_argument("--verify", metavar="FILE", help="check a backup instead of making one")
    backup.set_defaults(func=_cmd_backup)

    token = sub.add_parser("token", help="make an API token for the service (service.toml)")
    token.add_argument("--name", required=True, help="who it is for (recorded as operator)")
    token.add_argument("--role", choices=["viewer", "operator"], default="viewer")
    token.set_defaults(func=_cmd_token)

    enqueue = sub.add_parser("enqueue", help="queue a scan of a configured target (service)")
    enqueue.add_argument("target", help="the target's name in service.toml")
    enqueue.add_argument("--config", required=True, help="service.toml")
    enqueue.add_argument("--operator", help="who asks for it (default: user@host)")
    enqueue.set_defaults(func=_cmd_enqueue)

    worker = sub.add_parser("worker", help="run queued scans (service; needs Redis)")
    worker.add_argument("--config", required=True, help="service.toml")
    worker.add_argument("--burst", action="store_true", help="stop when the queue is empty")
    worker.set_defaults(func=_cmd_worker)

    scheduler = sub.add_parser("scheduler", help="queue the targets' scheduled scans")
    scheduler.add_argument("--config", required=True, help="service.toml")
    scheduler.add_argument("--once", action="store_true", help="one round, then stop")
    scheduler.set_defaults(func=_cmd_scheduler)

    web = sub.add_parser("web", help="serve the web API and dashboard (service)")
    web.add_argument("--config", required=True, help="service.toml")
    web.add_argument(
        "--host", default="127.0.0.1", help="address to listen on (default: local only)"
    )
    web.add_argument("--port", type=int, default=8000)
    web.set_defaults(func=_cmd_web)

    inventory = sub.add_parser("inventory", help="every host and port seen, across runs")
    inventory.add_argument("--db", default="reconkit.db", help="SQLite database path")
    inventory.add_argument(
        "--rebuild",
        action="store_true",
        help="rebuild it from the stored runs (decisions on findings are not replayed)",
    )
    inventory.set_defaults(func=_cmd_inventory)

    findings = sub.add_parser("findings", help="findings across runs, by lifecycle status")
    findings.add_argument("--db", default="reconkit.db", help="SQLite database path")
    findings.add_argument(
        "--status",
        action="append",
        choices=[str(s) for s in Status],
        help="only this status (repeatable; default: the ones still open)",
    )
    findings.add_argument("--all", action="store_true", help="every status")
    findings.set_defaults(func=_cmd_findings)

    finding = sub.add_parser("finding", help="one finding's history, or a decision about it")
    finding.add_argument("finding_id", type=int, help="the ID shown by `reconkit findings`")
    finding.add_argument("--db", default="reconkit.db", help="SQLite database path")
    decision = finding.add_mutually_exclusive_group()
    decision.add_argument(
        "--claim-fixed", action="store_true", help="say it is fixed: the next scan verifies it"
    )
    decision.add_argument(
        "--accept", action="store_true", help="accept the risk (needs --reason and --until)"
    )
    decision.add_argument("--reopen", action="store_true", help="open it again")
    finding.add_argument("--reason", help="why (required to accept a risk)")
    finding.add_argument("--until", help="review date of an accepted risk, YYYY-MM-DD")
    finding.add_argument("--operator", help="who decides (default: user@host)")
    finding.set_defaults(func=_cmd_finding)

    diff = sub.add_parser("diff", help="what changed between two runs")
    diff.add_argument("before", type=int, nargs="?", help="earlier run (default: see below)")
    diff.add_argument(
        "after", type=int, nargs="?", help="later run (default: the latest run and its predecessor)"
    )
    diff.add_argument("--db", default="reconkit.db", help="SQLite database path")
    diff.set_defaults(func=_cmd_diff)

    runs = sub.add_parser("runs", help="list the stored runs, newest first")
    runs.add_argument("--db", default="reconkit.db", help="SQLite database path")
    runs.add_argument("--limit", type=int, default=20, help="how many runs (default 20)")
    runs.set_defaults(func=_cmd_runs)

    report = sub.add_parser("report", help="write the report of a run (HTML map, JSON, SARIF)")
    report.add_argument("--run", type=int, help="id of the run (default: the latest)")
    report.add_argument("--db", default="reconkit.db", help="SQLite database path")
    report.add_argument("--html", help="a self-contained HTML report (map + tables)")
    report.add_argument("--json", help="the report data as JSON (format reconkit-report)")
    report.add_argument("--sarif", help="findings as SARIF 2.1.0 (DefectDojo, dashboards)")
    report.set_defaults(func=_cmd_report)
    return parser


class _Subparsers:
    """`add_subparsers()` result that gives every subcommand the logging options."""

    def __init__(self, actions: Any, common: argparse.ArgumentParser) -> None:
        self._actions = actions
        self._common = common

    def add_parser(self, name: str, **kwargs: Any) -> argparse.ArgumentParser:
        parser: argparse.ArgumentParser = self._actions.add_parser(
            name, parents=[self._common], **kwargs
        )
        return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        logs.setup(
            getattr(args, "verbose", 0),
            getattr(args, "log_file", None),
            getattr(args, "log_format", "text"),
        )
    except OSError as exc:
        print(f"error: cannot open the log file: {exc}", file=sys.stderr)
        return 2
    log.debug("reconkit %s: %s", __version__, " ".join(argv if argv is not None else sys.argv[1:]))
    func = args.func  # set by the chosen subcommand
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
