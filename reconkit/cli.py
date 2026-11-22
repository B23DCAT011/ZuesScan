"""Command-line entry point.

`reconkit scan <target> --scope <file>` wires the pieces together: load scope ->
build orchestrator with the nmap plugin -> run -> persist to SQLite -> print a summary.
`reconkit raw <run id>` gives back the scanner's own output kept for a run.
`reconkit runs` lists the stored runs; `reconkit report` turns one into a report.
`reconkit profiles` shows the scan profiles (`scan --profile`).
`reconkit cve sync|status|show` keeps a local copy of NVD to match CVEs against.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import os
import re
import sys
from pathlib import Path

from reconkit import priority
from reconkit.cve import CveDataError, CveSource, LocalCveSource
from reconkit.cve.cache import (
    CacheError,
    CveCache,
    NvdCveSource,
    refresh_epss,
    refresh_kev,
    sync,
)
from reconkit.cve.feeds import FeedError
from reconkit.cve.nvd import API_KEY_ENV, NvdClient, NvdError
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator, ScanRun, now
from reconkit.plugins.base import ScanError
from reconkit.plugins.nmap import NmapPlugin
from reconkit.profiles import DEFAULT_PROFILE, ProfileError, ScanProfile, load_profiles, override
from reconkit.report import render_html, report_model
from reconkit.schema import Asset, Finding
from reconkit.scope import ResolutionError, Scope, ScopeError
from reconkit.storage import SCHEMA_VERSION, Storage, StorageError


def _print_summary(run: ScanRun, run_id: int, db_path: str) -> None:
    services = [s for a in run.assets for s in a.services]
    findings = [f for a in run.assets for f in a.findings]
    print(f"\nScan run #{run_id}  target={run.target}  status={run.status}  (saved to {db_path})")
    tools = ", ".join(
        f"{name} {version or '(unknown version)'}" for name, version in run.tool_versions.items()
    )
    print(f"  scanners: {tools}")
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
        for f in sorted(asset.findings, key=priority.sort_key):
            sure = f", {f.confidence}" if f.confidence else ""
            print(
                f"    {priority.priority(f)} [{f.severity.upper()}{sure}] {f.title}"
                + (f" ({f.cve})" if f.cve else "")
            )
            print(f"        priority: {_risk_line(f)}")
            if f.evidence:
                print(f"        evidence: {f.evidence}")
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


def _indent(text: str, prefix: str = "  | ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def _profile(args: argparse.Namespace) -> ScanProfile:
    """The profile chosen with --profile (and --config), with the flags applied on top."""
    profiles = load_profiles(args.config)
    if args.profile not in profiles:
        raise ProfileError(
            f"unknown profile {args.profile!r}; choose one of: {', '.join(profiles)}"
        )
    return override(
        profiles[args.profile],
        {
            "ports": args.ports,
            "top_ports": args.top_ports,
            "timing": args.timing,
            "max_rate": args.max_rate,
            "host_timeout": args.host_timeout,
            "timeout": args.timeout,
            "traceroute": args.traceroute,
            "assume_up": True if args.assume_up else None,
        },
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        scope = Scope.from_file(args.scope)
    except FileNotFoundError:
        print(f"error: scope file not found: {args.scope}", file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(f"error: invalid scope file: {exc}", file=sys.stderr)
        return 2

    with contextlib.ExitStack() as stack:
        cve_source: CveSource | None = None
        try:
            if args.cve_cache:
                cve_source = NvdCveSource(stack.enter_context(CveCache(args.cve_cache)))
            elif not args.no_cve:
                # The bundled seed unless another data file is given.
                cve_source = LocalCveSource(args.cve_db) if args.cve_db else LocalCveSource()
        except (CveDataError, CacheError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        orch = Orchestrator(
            plugins=[NmapPlugin(profile=profile)],
            scope=scope,
            cve_source=cve_source,
            profile=profile,
            ipv4_only=args.ipv4_only,
        )
        return _open_db_and_scan(args, orch)


def _open_db_and_scan(args: argparse.Namespace, orch: Orchestrator) -> int:
    # Open the database before scanning: if the results cannot be saved, find out
    # now, not after probing the target for five minutes.
    try:
        store = Storage(args.db)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    with store:
        if store.backup_path:
            print(
                f"note: database upgraded to schema v{SCHEMA_VERSION}; "
                f"the previous version was kept at {store.backup_path}",
                file=sys.stderr,
            )
        return _scan(args, orch, store)


def _scan(args: argparse.Namespace, orch: Orchestrator, store: Storage) -> int:
    started = now()
    try:
        run = orch.run(args.target)
    except ScopeError as exc:
        # Refused before anything was probed: there is no run to record.
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except (NoPluginAvailableError, ResolutionError) as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return _record_failure(args, orch, store, started, exc)
    except ScanError as exc:
        print(f"scan failed [{exc.plugin}]: {exc}", file=sys.stderr)
        if exc.stderr:
            print(_indent(exc.stderr), file=sys.stderr)
        return _record_failure(args, orch, store, started, exc)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for note in run.notes:
        print(f"note: {note}", file=sys.stderr)
    if run.skipped_plugins:
        skipped = ", ".join(run.skipped_plugins)
        print(f"warning: skipped unavailable scanners: {skipped}", file=sys.stderr)
    if run.out_of_scope:
        dropped = ", ".join(run.out_of_scope)
        print(
            f"warning: a scanner reported hosts outside the scope; not saved: {dropped}",
            file=sys.stderr,
        )

    untraced = [a.host for a in run.assets if not a.route]
    if orch.profile is not None and orch.profile.traceroute and untraced:
        # Not an error: the scan itself is fine, only the map will lack these paths.
        print(
            f"note: no route recorded for {len(untraced)} of {len(run.assets)} host(s). "
            "Traceroute needs raw-socket privileges (root on Linux, Npcap on Windows), "
            "and a local target has no route.",
            file=sys.stderr,
        )

    run_id = store.save_run(run)
    _print_summary(run, run_id, args.db)
    return 0


def _record_failure(
    args: argparse.Namespace, orch: Orchestrator, store: Storage, started: str, exc: Exception
) -> int:
    """Store a failed scan as a `failed` run: no results, but the error is kept.

    Saving it as an ordinary empty run would read as "nothing found"; saving nothing
    would hide that the scan is broken.
    """
    run = orch.failed_run(args.target, started, exc)
    run_id = store.save_run(run)
    print(f"recorded as failed run #{run_id} in {args.db} (no results saved)", file=sys.stderr)
    if run.raw_outputs:
        print(
            f"the scanner's output was kept: reconkit raw {run_id} --db {args.db}",
            file=sys.stderr,
        )
    return 4


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
    if not _db_exists(args.db):
        return 2
    try:
        with Storage(args.db) as store:
            run_id = args.run if args.run is not None else store.latest_run_id()
            if run_id is None:
                print(f"error: no run stored in {args.db}", file=sys.stderr)
                return 2
            run = store.load_run(run_id)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if run is None:
        print(f"error: no run #{run_id} in {args.db}", file=sys.stderr)
        return 2

    page = render_html(report_model(run, run_id))
    try:
        Path(args.html).write_text(page, encoding="utf-8", newline="\n")
    except OSError as exc:
        print(f"error: cannot write {args.html}: {exc}", file=sys.stderr)
        return 1
    print(f"report of run #{run_id} ({run.target}, {run.status}) written to {args.html}")
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
        print(f"stderr:\n{_indent(output.stderr)}", file=sys.stderr)
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
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="Recon orchestrator & vulnerability management (academic project).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

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
    tuning.add_argument("--host-timeout", type=int, help="give up on one host after N seconds")
    tuning.add_argument("--timeout", type=int, help="stop the whole scan after N seconds")
    tuning.add_argument(
        "--traceroute",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="record the network path to each host (for the map; slower)",
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
    cve_sub = cve.add_subparsers(dest="cve_command", required=True)
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

    runs = sub.add_parser("runs", help="list the stored runs, newest first")
    runs.add_argument("--db", default="reconkit.db", help="SQLite database path")
    runs.add_argument("--limit", type=int, default=20, help="how many runs (default 20)")
    runs.set_defaults(func=_cmd_runs)

    report = sub.add_parser("report", help="write the report of a run (map + tables)")
    report.add_argument("--run", type=int, help="id of the run (default: the latest)")
    report.add_argument("--db", default="reconkit.db", help="SQLite database path")
    report.add_argument(
        "--html", required=True, help="write a self-contained HTML report to this file"
    )
    report.set_defaults(func=_cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func  # set by the chosen subcommand
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
