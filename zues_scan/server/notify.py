"""Alerts after a scan: what a person must look at, sent to a webhook.

Sent only for what changes the picture: a **fake fix** (claimed fixed, still there), a
finding that **reappeared**, and **new** findings at least as urgent as
`min_priority`. The payload is Slack-compatible (`{"text": ...}`) and also carries the
structured items, so other receivers (Teams via a workflow, a SIEM) can use them.
Standard library only.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from zues_scan import __version__, priority
from zues_scan.inventory_store import FindingEvent
from zues_scan.orchestrator import ScanRun

log = logging.getLogger(__name__)

Post = Callable[[str, bytes], None]


def alerts(
    run: ScanRun, changes: list[FindingEvent], min_priority: str = "P2"
) -> list[dict[str, Any]]:
    """What in this run deserves an alert, most serious first."""
    items: list[dict[str, Any]] = []
    for e in changes:
        if e.event in ("fake_fix", "reappeared"):
            items.append(
                {"kind": e.event, "finding_id": e.finding_id, "title": e.title, "host": e.host}
            )
    new = {e.fingerprint for e in changes if e.event == "new"}
    for asset in run.assets:
        for f in asset.findings:
            p = priority.priority(f)
            if f.fingerprint in new and str(p) <= min_priority:
                items.append(
                    {
                        "kind": "new",
                        "priority": str(p),
                        "title": f.title,
                        "cve": f.cve,
                        "host": asset.host,
                        "why": priority.reason(f),
                    }
                )
    order = {"fake_fix": 0, "reappeared": 1, "new": 2}
    return sorted(items, key=lambda i: (order[i["kind"]], i.get("priority", "")))


def message(target: str, run_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [f"ZuesScan: run #{run_id} of {target} needs attention"]
    for i in items[:20]:
        if i["kind"] == "fake_fix":
            lines.append(f"• FAKE FIX: {i['title']} on {i['host']} was claimed fixed, still there")
        elif i["kind"] == "reappeared":
            lines.append(f"• REAPPEARED: {i['title']} on {i['host']}")
        else:
            lines.append(f"• NEW {i['priority']}: {i['title']} on {i['host']} ({i['why']})")
    if len(items) > 20:
        lines.append(f"… and {len(items) - 20} more")
    return {"text": "\n".join(lines), "target": target, "run_id": run_id, "items": items}


def http_post(url: str, body: bytes) -> None:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"zues-scan/{__version__}"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        response.read()


def send(webhook: str, payload: dict[str, Any], post: Post | None = None) -> bool:
    """POST `payload`; False (and a logged warning) if it could not be delivered."""
    try:
        (post or http_post)(webhook, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        # The scan is saved either way; a lost alert must not fail the job.
        log.warning("could not deliver the alert to the webhook: %s", exc)
        return False
    return True
