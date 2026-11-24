"""The job a worker runs: scan one configured target, record it, send alerts.

Standard library + the core only, so that RQ can import it in any worker. The job
receives names, not settings: the service configuration is re-read in the worker, so
what is scanned is always what `service.toml` says *now*.

Alerts are queued in the database with the run (`notify.RunAlerts`), then sent right
away; what cannot be sent now waits for the scheduler's next round. A job that fails
without saving a run alerts through RQ's failure callback (`job_failed`).
"""

from __future__ import annotations

import logging
from typing import Any

from zues_scan.scanning import ScanSpec, execute
from zues_scan.server import notify
from zues_scan.server.config import ServiceConfig, Target, load_config

log = logging.getLogger(__name__)


def spec_for(config: ServiceConfig, target: Target, operator: str) -> ScanSpec:
    return ScanSpec(
        target=target.target,
        # A dashboard target's scope is text from the database; the run records its name.
        scope=target.scope if target.scope_text is None else f"dashboard scope {target.scope}",
        scope_text=target.scope_text,
        db=config.db,
        profile=target.profile,
        config=target.config,
        cve_cache=config.cve_cache,
        credentials=target.credentials,
        scanners=list(target.scanners),
        checks=list(target.checks),
        discoverers=list(target.discoverers),
        nuclei=target.nuclei,
        nuclei_templates=config.nuclei_templates,
        discover=target.discover,
        subfinder_config=config.subfinder_config,
        dns_wordlist=config.dns_wordlist,
        discover_limit=target.discover_limit,
        ipv4_only=target.ipv4_only,
        operator=operator,
        engagement=target.engagement,
        target_name=target.name,
        plugins=config.plugins,
    )


def scan_target(config_path: str, target_name: str, operator: str) -> dict[str, Any]:
    """Scan the target named `target_name` in the service config; return a summary."""
    config = load_config(config_path)
    target = config.target(target_name)
    log.info("job: scanning %s (%s) for %s", target.name, target.target, operator)
    policy = notify.RunAlerts(config.notify, target.name)
    spec = spec_for(config, target, operator)
    spec.alerts = policy
    outcome = execute(spec)
    summary: dict[str, Any] = {
        "target": target.name,
        "code": outcome.code,
        "run_id": outcome.run_id,
        "status": None if outcome.run is None else str(outcome.run.status),
        "messages": outcome.messages,
        "alerts": len(policy.items),
    }
    if outcome.run_id is None and outcome.code in (2, 3):
        # Refused by its scope (an authorisation that expired, an address that moved out
        # of it) or a setting that no longer holds: nothing was scanned, someone must know.
        reason = outcome.messages[0] if outcome.messages else f"exit code {outcome.code}"
        notify.queue(config, notify.not_started(target.name, reason))
    notify.flush(config)
    return summary


def job_failed(job: Any, connection: Any, kind: Any, value: Any, traceback: Any) -> None:
    """RQ's failure callback: the job raised, timed out or its worker died, so no run
    tells what happened. Never raises (RQ would only log it)."""
    try:
        config_path, target_name = str(job.args[0]), str(job.args[1])
        config = load_config(config_path)
    except Exception:  # noqa: BLE001 - e.g. the configuration itself is broken now
        log.exception("could not alert on the failed job %s", getattr(job, "id", "?"))
        return
    error = f"{getattr(kind, '__name__', kind)}: {value}" if value else str(kind)
    log.error("scan job of %s failed without saving a run: %s", target_name, error)
    notify.queue(config, notify.job_failed(target_name, error))
    notify.flush(config)
