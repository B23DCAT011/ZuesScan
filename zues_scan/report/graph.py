"""The attack-surface map of one run, as a graph (Cytoscape.js elements).

    scanner -> router -> router -> network ⊃ host ⊃ service -> finding

The map is *derived from what the scan saw*, it is not a wiring diagram: a switch, or
a router that never answered traceroute, does not appear. What the scanner could not
see is drawn as such — a dashed edge for routers that did not answer, a dotted one
for a host whose path was not traced — never guessed.

Pure functions, no I/O: the HTML report embeds the result as JSON, and the web UI can
serve the very same graph later.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from zues_scan import priority
from zues_scan.schema import Asset, Finding, Service, Severity

Element = dict[str, Any]

SCANNER = "scanner"

# Findings drawn per service; the others are summed up in one "+N more" node.
MAX_FINDINGS_PER_SERVICE = 5

# Hosts are grouped by the network they are in, as far as an address can tell: an
# IPv4 /24 or an IPv6 /64. The real subnet mask is not visible from outside.
_GROUP_PREFIX = {4: 24, 6: 64}


def severity_rank(severity: Severity | str) -> int:
    """0 for info ... 4 for critical."""
    return list(Severity).index(Severity(severity))


def worst(findings: list[Finding]) -> str | None:
    """The most serious severity among `findings`, or None if there are none."""
    if not findings:
        return None
    return str(max((f.severity for f in findings), key=severity_rank))


def network_of(ip: str | None) -> str | None:
    """The network a host is drawn in: its /24 (IPv4) or /64 (IPv6)."""
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = _GROUP_PREFIX[address.version]
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def host_id(asset: Asset) -> str:
    return f"host:{asset.ip or asset.host}"


def service_id(asset: Asset, port: int, protocol: str) -> str:
    return f"svc:{asset.ip or asset.host}:{port}/{protocol}"


def finding_id(finding: Finding) -> str:
    return f"finding:{finding.fingerprint or finding.compute_fingerprint()}"


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Element] = {}
        self.edges: dict[tuple[str, str], Element] = {}

    def node(self, node_id: str, kind: str, label: str, **data: Any) -> None:
        if node_id not in self.nodes:
            fields = {k: v for k, v in data.items() if v is not None}
            self.nodes[node_id] = {"data": {"id": node_id, "kind": kind, "label": label, **fields}}

    def edge(self, source: str, target: str, kind: str, **data: Any) -> None:
        key = (source, target)
        if key in self.edges:
            return  # the same link seen on the way to another host
        fields = {k: v for k, v in data.items() if v is not None}
        self.edges[key] = {
            "data": {
                "id": f"edge:{len(self.edges)}",
                "source": source,
                "target": target,
                "kind": kind,
                **fields,
            }
        }

    def elements(self) -> dict[str, list[Element]]:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values())}


def build_graph(assets: list[Asset]) -> dict[str, list[Element]]:
    """Nodes and edges for every host of a run, in Cytoscape.js element format.

    Each node's `data.ref` points back into the report's host list
    (`{"host": i}`, plus `"service": j` or `"finding": k`) so that the page can show the
    details of whatever is clicked.
    """
    graph = _Graph()
    graph.node(SCANNER, "scanner", "scanner")
    for index, asset in enumerate(assets):
        net = network_of(asset.ip)
        parent = f"net:{net}" if net else None
        if parent and net:
            graph.node(parent, "network", net)
        hid = host_id(asset)
        label = asset.host if asset.ip in (None, asset.host) else f"{asset.host}\n{asset.ip}"
        graph.node(
            hid,
            "host",
            label,
            parent=parent,
            severity=worst(asset.findings),
            ref={"host": index},
        )
        _path(graph, asset, end=parent or hid)

        for s_index, service in enumerate(asset.services):
            sid = service_id(asset, service.port, service.protocol)
            on_it = [f for f in asset.findings if _on(f, service)]
            what = " ".join(p for p in (service.product, service.version) if p)
            graph.node(
                sid,
                "service",
                f"{service.port}/{service.protocol} {service.name or '?'}"
                + (f"\n{what}" if what else ""),
                parent=hid,
                severity=worst(on_it),
                ref={"host": index, "service": s_index},
            )
        _findings(graph, asset, index, hid)
    return graph.elements()


def _findings(graph: _Graph, asset: Asset, index: int, hid: str) -> None:
    """Each finding hangs off its service (or its host); the most urgent ones only.

    A service with dozens of CVEs (an old database server easily has 60) would turn
    the map into a list: beyond `MAX_FINDINGS_PER_SERVICE`, the rest are drawn as one
    "+N more" node. The report's table still lists every finding.
    """
    by_source: dict[str, list[tuple[int, Finding]]] = {}
    for f_index, finding in enumerate(asset.findings):
        svc = finding.service
        source = service_id(asset, svc.port, svc.protocol) if svc else hid
        if source not in graph.nodes:
            source = hid  # a finding on a port the scan did not list as open
        by_source.setdefault(source, []).append((f_index, finding))
    for source, items in by_source.items():
        items.sort(key=lambda item: priority.sort_key(item[1]))
        for f_index, finding in items[:MAX_FINDINGS_PER_SERVICE]:
            fid = finding_id(finding)
            graph.node(
                fid,
                "finding",
                finding.cve or finding.rule_id or finding.title,
                parent=hid,
                severity=str(finding.severity),
                priority=str(priority.priority(finding)),
                ref={"host": index, "finding": f_index},
            )
            graph.edge(source, fid, "finding")
        rest = items[MAX_FINDINGS_PER_SERVICE:]
        if rest:
            more = f"more:{source}"
            graph.node(
                more,
                "more",
                f"+{len(rest)} more",
                parent=hid,
                severity=worst([f for _, f in rest]),
                ref={"host": index, "findings": [i for i, _ in rest]},
            )
            graph.edge(source, more, "finding")


def _path(graph: _Graph, asset: Asset, end: str) -> None:
    """Edges scanner -> each router that answered -> the host's network.

    The host itself is usually the last hop of its route; it is the end of the path,
    not a router. Routers that did not answer leave a gap in the TTLs, drawn as one
    dashed edge carrying how many were skipped.
    """
    if not asset.route:
        graph.edge(SCANNER, end, "untraced")
        return
    reaches_host = asset.route[-1].ip == asset.ip
    previous, previous_ttl = SCANNER, 0
    for hop in asset.route:
        if not hop.ip or hop.ip == asset.ip:
            continue  # no address to draw (it counts in the gap), or the host itself
        rid = f"hop:{hop.ip}"
        graph.node(rid, "router", hop.ip + (f"\n{hop.name}" if hop.name else ""), name=hop.name)
        if rid != previous:  # a router answering twice in a row is not a link
            _hop_edge(graph, previous, rid, skipped=hop.ttl - previous_ttl - 1)
        previous, previous_ttl = rid, hop.ttl
    if reaches_host:
        _hop_edge(graph, previous, end, skipped=asset.route[-1].ttl - previous_ttl - 1)
    else:
        # The trace stopped before the host: how far the rest is, nobody knows.
        graph.edge(previous, end, "incomplete")


def _hop_edge(graph: _Graph, source: str, target: str, skipped: int) -> None:
    if skipped > 0:
        graph.edge(source, target, "gap", skipped=skipped)
    else:
        graph.edge(source, target, "route")


def _on(finding: Finding, service: Service) -> bool:
    """Was `finding` found on `service` (same port and protocol)?"""
    svc = finding.service
    return svc is not None and (svc.port, svc.protocol) == (service.port, service.protocol)
