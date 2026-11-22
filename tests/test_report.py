"""Tests for the report: graph, model, and the self-contained HTML page."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from html.parser import HTMLParser
from importlib import resources
from typing import Any

import pytest

from reconkit.orchestrator import RunStatus, ScanRun
from reconkit.report import render_html, report_model
from reconkit.report.graph import build_graph, network_of
from reconkit.report.html import json_for_html
from reconkit.schema import Asset, Finding, Hop, Service, Severity

CYTOSCAPE_SHA256 = "081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8"

SSH = Service(port=22, name="ssh", product="OpenSSH", version="7.4")
HTTP = Service(port=80, name="http", product="nginx", version="1.18.0")
HOSTILE = "</script><script>alert(1)</script><!-- {{SCRIPT}} &  "


def _finding(service: Service | None, cve: str, severity: Severity, ip: str) -> Finding:
    f = Finding(asset=ip, ip=ip, title=f"issue {cve}", severity=severity, service=service, cve=cve)
    f.compute_fingerprint()
    return f


def _assets() -> list[Asset]:
    web = Asset(
        host="scanme.lab",
        ip="10.0.0.5",
        services=[SSH, HTTP],
        findings=[
            _finding(SSH, "CVE-2018-15473", Severity.MEDIUM, "10.0.0.5"),
            _finding(HTTP, "CVE-2021-23017", Severity.HIGH, "10.0.0.5"),
            _finding(None, "CVE-0000-0001", Severity.LOW, "10.0.0.5"),
        ],
        route=[Hop(1, "192.168.1.1", 0.5, "gw.lan"), Hop(3, "10.0.0.1"), Hop(4, "10.0.0.5")],
    )
    quiet = Asset(host="10.0.0.7", ip="10.0.0.7")  # up, nothing open, not traced
    return [web, quiet]


def _run(assets: list[Asset] | None = None) -> ScanRun:
    return ScanRun(
        "10.0.0.0/24",
        "2026-11-22T10:00:00+00:00",
        "2026-11-22T10:01:00+00:00",
        assets=_assets() if assets is None else assets,
        tool_versions={"nmap": "7.992"},
    )


def _edges(graph: dict[str, list[dict[str, Any]]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(e["data"]["source"], e["data"]["target"]): e["data"] for e in graph["edges"]}


def _nodes(graph: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    return {n["data"]["id"]: n["data"] for n in graph["nodes"]}


# --- vendored library ----------------------------------------------------------------


def test_vendored_cytoscape_is_the_pinned_file() -> None:
    data = resources.files("reconkit.report").joinpath("vendor/cytoscape.min.js").read_bytes()
    assert hashlib.sha256(data).hexdigest() == CYTOSCAPE_SHA256
    readme = resources.files("reconkit.report").joinpath("vendor/README.md").read_text("utf-8")
    assert CYTOSCAPE_SHA256 in readme


# --- graph -----------------------------------------------------------------------------


def test_path_goes_scanner_routers_network() -> None:
    graph = build_graph(_assets())
    nodes, edges = _nodes(graph), _edges(graph)
    assert nodes["hop:192.168.1.1"]["kind"] == "router"
    assert nodes["hop:192.168.1.1"]["name"] == "gw.lan"
    assert edges[("scanner", "hop:192.168.1.1")]["kind"] == "route"
    # TTL 2 never answered: one dashed edge that says so, no invented router.
    gap = edges[("hop:192.168.1.1", "hop:10.0.0.1")]
    assert (gap["kind"], gap["skipped"]) == ("gap", 1)
    assert edges[("hop:10.0.0.1", "net:10.0.0.0/24")]["kind"] == "route"
    assert "hop:10.0.0.5" not in nodes  # the host is the end of its path, not a router


def test_hosts_sit_in_their_network_and_services_in_their_host() -> None:
    nodes = _nodes(build_graph(_assets()))
    assert nodes["net:10.0.0.0/24"]["kind"] == "network"
    assert nodes["host:10.0.0.5"]["parent"] == "net:10.0.0.0/24"
    assert nodes["host:10.0.0.5"]["label"] == "scanme.lab\n10.0.0.5"
    assert nodes["host:10.0.0.7"]["label"] == "10.0.0.7"
    assert nodes["svc:10.0.0.5:22/tcp"]["parent"] == "host:10.0.0.5"
    assert nodes["svc:10.0.0.5:22/tcp"]["label"] == "22/tcp ssh\nOpenSSH 7.4"


def test_untraced_host_is_linked_to_the_scanner_as_such() -> None:
    edges = _edges(build_graph([Asset(host="172.16.0.9", ip="172.16.0.9")]))
    assert edges[("scanner", "net:172.16.0.0/24")]["kind"] == "untraced"


def test_trace_that_stops_before_the_host_is_incomplete() -> None:
    asset = Asset(host="10.0.0.5", ip="10.0.0.5", route=[Hop(1, "192.168.1.1")])
    assert _edges(build_graph([asset]))[("hop:192.168.1.1", "net:10.0.0.0/24")]["kind"] == (
        "incomplete"
    )


def test_router_answering_twice_is_not_a_loop_and_unnamed_hops_count_as_silent() -> None:
    route = [Hop(1, "192.168.1.1"), Hop(2, "192.168.1.1"), Hop(3, None), Hop(4, "10.0.0.5")]
    edges = _edges(build_graph([Asset(host="10.0.0.5", ip="10.0.0.5", route=route)]))
    assert ("hop:192.168.1.1", "hop:192.168.1.1") not in edges
    assert edges[("hop:192.168.1.1", "net:10.0.0.0/24")]["skipped"] == 1  # TTL 3


def test_shared_routers_are_drawn_once() -> None:
    a, b = _assets()
    b.route = [Hop(1, "192.168.1.1"), Hop(3, "10.0.0.1"), Hop(4, "10.0.0.7")]
    graph = build_graph([a, b])
    assert [n for n in _nodes(graph) if n.startswith("hop:")] == [
        "hop:192.168.1.1",
        "hop:10.0.0.1",
    ]
    assert len(graph["edges"]) == len(_edges(graph))  # no duplicate link


def test_findings_hang_off_their_service_and_colour_it() -> None:
    graph = build_graph(_assets())
    nodes, edges = _nodes(graph), _edges(graph)
    high = next(n for n in nodes.values() if n.get("label") == "CVE-2021-23017")
    assert high["severity"] == "high"
    assert edges[("svc:10.0.0.5:80/tcp", high["id"])]["kind"] == "finding"
    loose = next(n for n in nodes.values() if n.get("label") == "CVE-0000-0001")
    assert ("host:10.0.0.5", loose["id"]) in edges  # no service: hangs off the host
    assert nodes["svc:10.0.0.5:80/tcp"]["severity"] == "high"
    assert nodes["host:10.0.0.5"]["severity"] == "high"  # the worst on the host
    assert "severity" not in nodes["host:10.0.0.7"]


def test_every_node_ref_points_into_the_host_list() -> None:
    assets = _assets()
    for node in _nodes(build_graph(assets)).values():
        ref = node.get("ref")
        if ref is None:
            continue
        asset = assets[ref["host"]]
        if "service" in ref:
            assert node["id"].endswith(f":{asset.services[ref['service']].port}/tcp")
        if "finding" in ref:
            assert node["id"] == f"finding:{asset.findings[ref['finding']].fingerprint}"


@pytest.mark.parametrize(
    ("ip", "network"),
    [
        ("10.0.0.5", "10.0.0.0/24"),
        ("2001:db8::5", "2001:db8::/64"),
        (None, None),
        ("not-an-ip", None),
    ],
)
def test_hosts_are_grouped_by_prefix(ip: str | None, network: str | None) -> None:
    assert network_of(ip) == network


# --- model -----------------------------------------------------------------------------


def test_model_summarises_the_run() -> None:
    model = report_model(_run(), 7)
    assert model["format"] == "reconkit-report"
    assert model["run"]["id"] == 7
    assert model["run"]["scanners"] == [{"name": "nmap", "version": "7.992"}]
    assert model["run"]["profile"] is None
    assert model["summary"] == {
        "hosts": 2,
        "services": 2,
        "findings": 3,
        "traced_hosts": 1,
        "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0},
    }
    web = model["hosts"][0]
    assert web["findings"][1]["port"] == 80
    assert web["route"][0] == {"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 0.5, "name": "gw.lan"}
    json.dumps(model, allow_nan=False)  # plain JSON data, nothing else


def test_model_of_a_failed_run_carries_the_error() -> None:
    run = _run([])
    run.status, run.error, run.failed_plugin = RunStatus.FAILED, "nmap timed out", "nmap"
    model = report_model(run, 1)
    assert (model["run"]["status"], model["run"]["error"]) == ("failed", "nmap timed out")
    assert model["run"]["failed_scanner"] == "nmap"
    assert model["hosts"] == []


# --- HTML ------------------------------------------------------------------------------


def test_json_for_html_cannot_break_out_of_its_script_element() -> None:
    text = json_for_html({"banner": HOSTILE})
    for bad in ("<", ">", "&", " "):
        assert bad not in text
    assert json.loads(text) == {"banner": HOSTILE}  # same data once parsed


class _Page(HTMLParser):
    """Collects the CSP and the content of every <script> / <style> element."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp = ""
        self.links: list[str] = []  # src= / href= of any element: what would be fetched
        self.blocks: list[tuple[str, dict[str, str | None], str]] = []
        self._open: tuple[str, dict[str, str | None]] | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.links += [v or "" for k, v in attrs if k in ("src", "href")]
        if tag == "meta" and values.get("http-equiv") == "Content-Security-Policy":
            self.csp = values.get("content") or ""
        if tag in ("script", "style"):
            self._open, self._text = (tag, values), []

    def handle_data(self, data: str) -> None:
        if self._open:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._open and tag == self._open[0]:
            self.blocks.append((tag, self._open[1], "".join(self._text)))
            self._open = None


def _page(run: ScanRun) -> tuple[str, _Page]:
    page = render_html(report_model(run, 1))
    parser = _Page()
    parser.feed(page)
    return page, parser


def _sha(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def test_page_embeds_data_library_and_script_and_nothing_else() -> None:
    page, parsed = _page(_run())
    kinds = [(tag, attrs.get("type")) for tag, attrs, _ in parsed.blocks]
    assert kinds == [
        ("style", None),
        ("script", "application/json"),
        ("script", None),
        ("script", None),
    ]
    data = json.loads(parsed.blocks[1][2])
    assert data["run"]["target"] == "10.0.0.0/24"
    assert parsed.links == []  # nothing is loaded from anywhere: the file works offline


def test_csp_allows_exactly_the_inlined_code_and_no_network() -> None:
    _, parsed = _page(_run())
    directives = dict(d.strip().split(" ", 1) for d in parsed.csp.split(";"))
    assert directives["default-src"] == "'none'"
    style, _, cytoscape, script = (block[2] for block in parsed.blocks)
    assert directives["script-src"].split() == [_sha(cytoscape), _sha(script)]
    assert directives["style-src"] == _sha(style)
    assert "unsafe" not in parsed.csp
    assert "connect-src" not in directives  # falls back to 'none': the page cannot call out


def test_hostile_scan_data_stays_data() -> None:
    svc = Service(port=8080, name="http", product=HOSTILE, banner=HOSTILE)
    page, parsed = _page(_run([Asset(host="10.0.0.9", ip="10.0.0.9", services=[svc])]))
    assert len(parsed.blocks) == 4  # no extra <script> element appeared
    assert "<script>alert(1)" not in page
    # Placeholders are filled in one pass over the template: "{{SCRIPT}}" in the data
    # is left as it is, not replaced by the page script.
    assert "{{SCRIPT}}" in parsed.blocks[1][2]
    product = json.loads(parsed.blocks[1][2])["hosts"][0]["services"][0]["product"]
    assert product == HOSTILE  # the text itself is kept, exactly


def test_title_is_escaped() -> None:
    run = _run([])
    run.target = "<b>x</b>"
    page, _ = _page(run)
    assert "<title>ReconKit — run #1 — &lt;b&gt;x&lt;/b&gt;</title>" in page


def test_page_script_never_writes_markup() -> None:
    script = resources.files("reconkit.report").joinpath("assets/report.js").read_text("utf-8")
    code = re.sub(r"/\*.*?\*/", "", script, flags=re.S)  # the header comment names them
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code
