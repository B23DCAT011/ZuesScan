"""The report model: everything a report shows about one run, as plain JSON data.

One model, several renderings: the HTML report embeds it, and the JSON export and the
web UI can reuse it. It carries data only, never markup: whatever a scanned machine
said about itself (a banner, a product name) stays a string, and each renderer must
treat it as untrusted text.
"""

from __future__ import annotations

from typing import Any

from zues_scan import __version__, priority
from zues_scan.orchestrator import ScanRun, now
from zues_scan.report.graph import build_graph
from zues_scan.schema import Asset, Finding, Hop, Service, Severity
from zues_scan.storage import Storage

# Bump when a field changes meaning or disappears; adding a field is not a new version.
MODEL_VERSION = 1


def report_model(
    run: ScanRun,
    run_id: int,
    *,
    statuses: dict[str, str] | None = None,
    changes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the report model of `run` (stored as run `run_id`).

    `statuses` (fingerprint -> lifecycle status) and `changes` (what this run changed
    in the inventory) come from the database; without them the report shows the run
    on its own.
    """
    findings = [f for a in run.assets for f in a.findings]
    by_severity = {str(s): 0 for s in reversed(Severity)}
    for f in findings:
        by_severity[str(f.severity)] += 1
    return {
        "format": "zues-report",
        "version": MODEL_VERSION,
        "generated_at": now(),
        "generated_by": f"zues {__version__}",
        "run": {
            "id": run_id,
            "target": run.target,
            "status": str(run.status),
            "error": run.error,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "zues_version": run.zues_version,
            "profile": run.profile,
            "profile_settings": run.profile_settings,
            "scanners": [
                {"name": name, "version": version} for name, version in run.tool_versions.items()
            ],
            "skipped_scanners": list(run.skipped_plugins),
            "failed_scanner": run.failed_plugin,
            "out_of_scope": list(run.out_of_scope),
            "notes": list(run.notes),
            "operator": run.operator,
            "engagement": run.engagement,
            "scope_path": run.scope_path,
            "scope_sha256": run.scope_sha256,
            "plan": None
            if run.plan is None
            else {
                "addresses": list(run.plan.addresses),
                "exclude": list(run.plan.exclude),
                "hostname": run.plan.hostname,
            },
            "raw_outputs": [
                {"plugin": o.plugin, "format": o.format, "size": o.size, "sha256": o.sha256}
                for o in run.raw_outputs
            ],
        },
        "summary": {
            "hosts": len(run.assets),
            "services": sum(len(a.services) for a in run.assets),
            "findings": len(findings),
            "traced_hosts": sum(1 for a in run.assets if a.route),
            "by_severity": by_severity,
            "by_priority": {
                str(p): sum(1 for f in findings if priority.priority(f) == p)
                for p in priority.Priority
            },
            "known_exploited": sum(1 for f in findings if f.kev_added),
        },
        "hosts": [_host(a, statuses or {}) for a in run.assets],
        "changes": list(changes or []),
        "graph": build_graph(run.assets),
    }


def stored_model(store: Storage, run_id: int) -> dict[str, Any] | None:
    """The report model of stored run `run_id`, with each finding's lifecycle status
    and what the run changed in the inventory; None if there is no such run."""
    run = store.load_run(run_id)
    if run is None:
        return None
    changes = [
        {
            "finding_id": e.finding_id,
            "event": e.event,
            "from": e.old_status,
            "to": e.new_status,
            "title": e.title,
            "host": e.host,
        }
        for e in store.changes_in_run(run_id)
    ]
    return report_model(run, run_id, statuses=store.finding_statuses(), changes=changes)


def _host(asset: Asset, statuses: dict[str, str]) -> dict[str, Any]:
    # Same order as the run: the graph refers to services and findings by position.
    return {
        "host": asset.host,
        "ip": asset.ip,
        "names": list(asset.names),
        "services": [_service(s) for s in asset.services],
        "findings": [
            {**_finding(f), "status": statuses.get(f.fingerprint)} for f in asset.findings
        ],
        "route": [_hop(h) for h in asset.route],
    }


def _service(s: Service) -> dict[str, Any]:
    return {
        "port": s.port,
        "protocol": s.protocol,
        "state": s.state,
        "name": s.name,
        "product": s.product,
        "version": s.version,
        "cpe": s.cpe,
        "banner": s.banner,
    }


def _finding(f: Finding) -> dict[str, Any]:
    return {
        "title": f.title,
        "severity": str(f.severity),
        "cve": f.cve,
        "rule_id": f.rule_id,
        "confidence": None if f.confidence is None else str(f.confidence),
        "priority": str(priority.priority(f)),
        "priority_reason": priority.reason(f),
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "cwe": list(f.cwe),
        "kev_added": f.kev_added,
        "epss": f.epss,
        "port": f.service.port if f.service else None,
        "protocol": f.service.protocol if f.service else None,
        "description": f.description,
        "evidence": f.evidence,
        "fingerprint": f.fingerprint,
    }


def _hop(h: Hop) -> dict[str, Any]:
    return {"ttl": h.ttl, "ip": h.ip, "rtt_ms": h.rtt_ms, "name": h.name}
