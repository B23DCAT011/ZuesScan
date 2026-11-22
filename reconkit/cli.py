"""Command-line entry point.

`reconkit scan <target> --scope <file>` wires the pieces together: load scope ->
build orchestrator with the nmap plugin -> run -> persist to SQLite -> print a summary.
`reconkit raw <run id>` gives back the scanner's own output kept for a run.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from reconkit.cve import LocalCveSource
from reconkit.orchestrator import NoPluginAvailableError, Orchestrator, ScanRun, now
from reconkit.plugins.base import ScanError
from reconkit.plugins.nmap import NmapPlugin
from reconkit.schema import Asset
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
        for f in asset.findings:
            print(f"    [{f.severity.upper()}] {f.title}" + (f" ({f.cve})" if f.cve else ""))
            if f.evidence:
                print(f"        evidence: {f.evidence}")
    for o in run.raw_outputs:
        print(
            f"\n  raw output kept: {o.plugin} ({o.format}, {o.size} bytes, "
            f"sha256 {o.sha256[:12]}...)  ->  reconkit raw {run_id} --db {db_path}"
        )


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


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scope = Scope.from_file(args.scope)
    except FileNotFoundError:
        print(f"error: scope file not found: {args.scope}", file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(f"error: invalid scope file: {exc}", file=sys.stderr)
        return 2

    if args.no_cve:
        cve_source = None
    elif args.cve_db:
        cve_source = LocalCveSource(args.cve_db)
    else:
        cve_source = LocalCveSource()  # bundled seed
    orch = Orchestrator(
        plugins=[NmapPlugin(traceroute=args.traceroute)], scope=scope, cve_source=cve_source
    )

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
    if args.traceroute and untraced:
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


def _cmd_raw(args: argparse.Namespace) -> int:
    """Print (or save) the raw scanner output stored for a run."""
    if not Path(args.db).is_file():
        print(f"error: database not found: {args.db}", file=sys.stderr)
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

    if args.plugin:
        outputs = [o for o in outputs if o.plugin == args.plugin]
    if not outputs:
        which = f" from {args.plugin}" if args.plugin else ""
        print(f"error: run #{args.run_id} has no raw output{which} stored", file=sys.stderr)
        return 1
    if len(outputs) > 1:
        names = ", ".join(o.plugin for o in outputs)
        print(
            f"error: run has several raw outputs ({names}); pick one with --plugin", file=sys.stderr
        )
        return 2

    (output,) = outputs
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
    scan.add_argument("--no-cve", action="store_true", help="skip the CVE matching stage")
    scan.add_argument("--cve-db", help="path to a CVE seed JSON (default: bundled seed)")
    scan.add_argument(
        "--traceroute",
        action="store_true",
        help="also record the network path to each host (for the map; slower)",
    )
    scan.set_defaults(func=_cmd_scan)

    raw = sub.add_parser("raw", help="show the raw scanner output kept for a run")
    raw.add_argument("run_id", type=int, help="id of the run, as printed by `scan`")
    raw.add_argument("--db", default="reconkit.db", help="SQLite database path")
    raw.add_argument("--plugin", help="which scanner's output, if the run has several")
    raw.add_argument("--out", help="write the output to this file instead of the screen")
    raw.set_defaults(func=_cmd_raw)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func  # set by the chosen subcommand
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
