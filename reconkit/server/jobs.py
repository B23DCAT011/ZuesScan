"""The job a worker runs: scan one configured target, record it, send alerts.

Standard library + the core only, so that RQ can import it in any worker. The job
receives names, not settings: the service configuration is re-read in the worker, so
what is scanned is always what `service.toml` says *now*.
"""

from __future__ import annotations

import logging
from typing import Any

from reconkit.scanning import ScanSpec, execute
from reconkit.server import notify
from reconkit.server.config import ServiceConfig, Target, load_config

log = logging.getLogger(__name__)


def spec_for(config: ServiceConfig, target: Target, operator: str) -> ScanSpec:
    return ScanSpec(
        target=target.target,
        scope=target.scope,
        db=config.db,
        profile=target.profile,
        config=target.config,
        cve_cache=config.cve_cache,
        credentials=target.credentials,
        nuclei=target.nuclei,
        nuclei_templates=config.nuclei_templates,
        discover=target.discover,
        subfinder_config=config.subfinder_config,
        discover_limit=target.discover_limit,
        ipv4_only=target.ipv4_only,
        operator=operator,
        engagement=target.engagement,
    )


def scan_target(config_path: str, target_name: str, operator: str) -> dict[str, Any]:
    """Scan the target named `target_name` in the service config; return a summary."""
    config = load_config(config_path)
    target = config.target(target_name)
    log.info("job: scanning %s (%s) for %s", target.name, target.target, operator)
    outcome = execute(spec_for(config, target, operator))
    summary: dict[str, Any] = {
        "target": target.name,
        "code": outcome.code,
        "run_id": outcome.run_id,
        "status": None if outcome.run is None else str(outcome.run.status),
        "messages": outcome.messages,
        "alerts": 0,
    }
    if outcome.run is not None and outcome.run_id is not None and outcome.code == 0:
        items = notify.alerts(outcome.run, outcome.changes, config.notify.min_priority)
        summary["alerts"] = len(items)
        if items and config.notify.webhook:
            notify.send(config.notify.webhook, notify.message(target.name, outcome.run_id, items))
    return summary
