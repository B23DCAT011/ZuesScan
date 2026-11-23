"""SARIF 2.1.0 export (G18): findings in the format security tools exchange.

SARIF (Static Analysis Results Interchange Format, an OASIS standard) is read by
vulnerability managers such as DefectDojo, and by most security dashboards. It was
made for source code, so a network finding is placed with a *logical* location (the
host and port) plus an artifact URI of the form `tcp://10.0.0.5:22`.

Mapping, per finding:

* `ruleId`: the CVE, else the check's rule id; each rule says what the issue is
  (description, CWE, CVSS, a link to NVD for CVEs).
* `level`: critical / high -> error, medium -> warning, low / info -> note.
* `rank`: the CVSS score x 10 (0-100), SARIF's "how serious" scale.
* `partialFingerprints["zues_scan/v2"]`: ZuesScan's fingerprint, so a consumer can
  recognise the same issue across runs exactly as ZuesScan does.
* `properties`: priority, confidence, EPSS, KEV listing, lifecycle status.
"""

from __future__ import annotations

from typing import Any

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(model: dict[str, Any]) -> dict[str, Any]:
    """A SARIF log with one run, from a report model (see `report_model`)."""
    run = model["run"]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for host in model["hosts"]:
        address = host["ip"] or host["host"]
        for f in host["findings"]:
            rule_id = f["cve"] or f["rule_id"] or _slug(f["title"])
            if rule_id not in rules:
                rules[rule_id] = _rule(rule_id, f)
            results.append(_result(rule_id, list(rules).index(rule_id), host, address, f))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ZuesScan",
                        "version": model["generated_by"].split()[-1],
                        "informationUri": "https://github.com/B23DCAT011/reconkit",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": run["status"] != "failed",
                        "startTimeUtc": run["started_at"],
                        "endTimeUtc": run["finished_at"],
                        **({"exitCodeDescription": run["error"]} if run["error"] else {}),
                    }
                ],
                "automationDetails": {"id": f"zues_scan/{run['target']}/run-{run['id']}"},
                "results": results,
                "properties": _bag(
                    {
                        "target": run["target"],
                        "status": run["status"],
                        "profile": run.get("profile"),
                        "scanners": run["scanners"],
                        "engagement": run.get("engagement"),
                        "operator": run.get("operator"),
                    }
                ),
            }
        ],
    }


def _rule(rule_id: str, f: dict[str, Any]) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f["description"] or f["title"]},
        "defaultConfiguration": {"level": _LEVEL.get(f["severity"], "warning")},
        "properties": {"tags": ["security", *f.get("cwe", [])]},
    }
    if f["cve"]:
        rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{f['cve']}"
    if f.get("cvss_score") is not None:
        # GitHub and others read this property to sort by severity.
        rule["properties"]["security-severity"] = f"{f['cvss_score']:.1f}"
    return rule


def _result(
    rule_id: str, index: int, host: dict[str, Any], address: str, f: dict[str, Any]
) -> dict[str, Any]:
    where = f"{address}:{f['port']}/{f['protocol']}" if f["port"] else address
    uri = f"{f['protocol'] or 'tcp'}://{_uri_host(address)}" + (
        f":{f['port']}" if f["port"] else ""
    )
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": index,
        "level": _LEVEL.get(f["severity"], "warning"),
        "message": {
            "text": f"{f['title']} on {where}" + (f": {f['evidence']}" if f["evidence"] else "")
        },
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocations": [
                    {
                        "name": where,
                        "fullyQualifiedName": f"{host['host']}/{where}",
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {"zues_scan/v2": f["fingerprint"]},
        "properties": {
            "priority": f.get("priority"),
            "priorityReason": f.get("priority_reason"),
            "confidence": f.get("confidence"),
            "epss": f.get("epss"),
            "kevAdded": f.get("kev_added"),
            "status": f.get("status"),
            "host": host["host"],
        },
    }
    if f.get("cvss_score") is not None:
        result["rank"] = round(f["cvss_score"] * 10, 1)
    result["properties"] = _bag(result["properties"])
    return result


def _bag(values: dict[str, Any]) -> dict[str, Any]:
    """A SARIF property bag without empty entries."""
    return {k: v for k, v in values.items() if v is not None}


def _uri_host(address: str) -> str:
    return f"[{address}]" if ":" in address else address  # IPv6 in a URI


def _slug(title: str) -> str:
    return "zues-" + "-".join(title.lower().split())[:60]
