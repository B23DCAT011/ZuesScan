/* ReconKit HTML report — page script. Inlined into every report; its SHA-256 is in the
   page's CSP.

   Every string in the data came from a scanned machine and may be hostile. This
   script therefore only ever puts data into the page as TEXT: element.textContent,
   or a Cytoscape label (drawn on a canvas). It never uses innerHTML, never builds
   markup from strings, never evaluates anything. */
(function () {
  "use strict";

  var data = JSON.parse(document.getElementById("reconkit-data").textContent);
  var run = data.run;
  var SEVERITIES = ["critical", "high", "medium", "low", "info"];

  /* --- helpers ------------------------------------------------------------------ */

  // el("td", {class: "x"}, "text", childNode, ...) — children are text or nodes.
  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        if (attrs[key] !== null && attrs[key] !== undefined) node.setAttribute(key, attrs[key]);
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      var child = arguments[i];
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function sevRank(sev) {
    var i = SEVERITIES.indexOf(sev);
    return i < 0 ? SEVERITIES.length : i;
  }

  function sevBadge(sev) {
    return el("span", { class: "sev sev-" + sev }, sev);
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function when(iso) {
    if (!iso) return "-";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function seconds(a, b) {
    var t = (new Date(b) - new Date(a)) / 1000;
    return isNaN(t) ? "" : (t < 90 ? t.toFixed(1) + " s" : (t / 60).toFixed(1) + " min");
  }

  function service(svc) {
    return svc.port + "/" + svc.protocol;
  }

  function productLine(svc) {
    return [svc.product, svc.version].filter(Boolean).join(" ") || "-";
  }

  /* --- header ------------------------------------------------------------------- */

  function renderHeader() {
    document.getElementById("title").textContent = "Run #" + run.id + " — " + run.target;
    var meta = document.getElementById("meta");
    meta.appendChild(el("span", { class: "badge status-" + run.status }, run.status));
    meta.appendChild(el("span", null, "started " + when(run.started_at)));
    meta.appendChild(el("span", null, "took " + seconds(run.started_at, run.finished_at)));
    var scanners = run.scanners.map(function (s) {
      return s.name + " " + (s.version || "(unknown version)");
    });
    if (scanners.length) meta.appendChild(el("span", null, "scanners: " + scanners.join(", ")));
    if (run.profile) meta.appendChild(el("span", null, "profile: " + run.profile));

    if (run.error) {
      var box = document.getElementById("error");
      box.hidden = false;
      box.textContent = "This scan failed" +
        (run.failed_scanner ? " in " + run.failed_scanner : "") + ": " + run.error +
        "\nA failed run has no results: it does not mean that nothing was found.";
    }

    var s = data.summary;
    var tiles = document.getElementById("tiles");
    function tile(n, label, cls) {
      tiles.appendChild(el("div", { class: "tile" }, el("div", { class: "n " + (cls || "") }, n),
        el("div", { class: "k" }, label)));
    }
    tile(s.hosts, s.hosts === 1 ? "host" : "hosts");
    tile(s.services, "open services");
    tile(s.findings, s.findings === 1 ? "finding" : "findings");
    SEVERITIES.forEach(function (sev) {
      if (s.by_severity[sev]) tile(s.by_severity[sev], sev, "sev-" + sev);
    });
    tile(s.traced_hosts + "/" + s.hosts, "hosts traced");
  }

  /* --- map ---------------------------------------------------------------------- */

  var cy = null;

  function sevColor(sev) {
    return cssVar("--sev-" + (sev || "none"));
  }

  function buildMap() {
    if (typeof cytoscape !== "function") return;
    var text = cssVar("--text");
    var muted = cssVar("--muted");
    var line = cssVar("--line");
    var panel = cssVar("--panel");
    cy = cytoscape({
      container: document.getElementById("map"),
      elements: data.graph,
      minZoom: 0.1,
      maxZoom: 2,
      style: [
        { selector: "node", style: {
          "label": "data(label)", "font-size": 10, "color": text, "font-family": cssVar("--font"),
          "text-wrap": "wrap", "text-max-width": 160, "text-valign": "bottom", "text-margin-y": 4,
          "background-color": muted, "width": 18, "height": 18,
          "text-background-color": panel, "text-background-opacity": 0.75,
          "text-background-padding": 1 } },
        { selector: 'node[kind = "scanner"]', style: {
          "shape": "diamond", "width": 30, "height": 30, "background-color": cssVar("--accent"),
          "font-weight": "bold" } },
        { selector: 'node[kind = "router"]', style: {
          "shape": "round-rectangle", "width": 22, "height": 14,
          "background-color": cssVar("--router") } },
        { selector: 'node[kind = "network"]', style: {
          "shape": "round-rectangle", "background-color": cssVar("--network"),
          "background-opacity": 0.07, "border-width": 1, "border-style": "dashed",
          "border-color": cssVar("--network"), "text-valign": "top", "text-halign": "center",
          "text-margin-y": -4, "font-size": 11, "font-weight": "bold", "padding": 18,
          "color": muted } },
        { selector: 'node[kind = "host"]', style: {
          "shape": "round-rectangle", "background-color": panel, "background-opacity": 1,
          "border-width": 2, "border-color": sevColor(null), "text-valign": "top",
          "text-halign": "center", "text-margin-y": -3, "font-size": 11, "font-weight": "bold",
          "padding": 10, "width": 36, "height": 24 } },
        { selector: 'node[kind = "host"][severity]', style: {
          "border-color": function (n) { return sevColor(n.data("severity")); } } },
        { selector: 'node[kind = "service"]', style: {
          "shape": "ellipse", "width": 14, "height": 14, "font-size": 9,
          "text-valign": "center", "text-halign": "right", "text-margin-x": 6,
          "text-margin-y": 0, "background-color": cssVar("--service") } },
        { selector: 'node[kind = "service"][severity]', style: {
          "background-color": function (n) { return sevColor(n.data("severity")); } } },
        { selector: 'node[kind = "finding"]', style: {
          "shape": "tag", "width": 16, "height": 16, "font-size": 9,
          "text-valign": "center", "text-halign": "right", "text-margin-x": 6,
          "text-margin-y": 0,
          "background-color": function (n) { return sevColor(n.data("severity")); } } },
        { selector: "edge", style: {
          "width": 1.5, "line-color": line, "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": line, "arrow-scale": 0.8 } },
        { selector: 'edge[kind = "gap"]', style: {
          "line-style": "dashed", "label": function (e) {
            var n = e.data("skipped");
            return n + " silent hop" + (n === 1 ? "" : "s");
          }, "font-size": 9, "color": muted, "text-background-color": panel,
          "text-background-opacity": 0.8 } },
        { selector: 'edge[kind = "untraced"], edge[kind = "incomplete"]', style: {
          "line-style": "dotted" } },
        { selector: 'edge[kind = "finding"]', style: { "width": 1, "arrow-scale": 0.6 } },
        { selector: ":selected", style: {
          "border-width": 3, "border-color": cssVar("--accent"), "line-color": cssVar("--accent"),
          "target-arrow-color": cssVar("--accent") } }
      ],
      layout: layoutOptions("path")
    });

    cy.on("tap", "node", function (evt) { showDetails(evt.target); });
    cy.on("tap", function (evt) { if (evt.target === cy) showOverview(); });
  }

  // "path": a fixed, left-to-right reading of the scan — scanner, then the routers in
  // the order they were met, then each network with its hosts stacked; inside a host,
  // its services in a column and each finding next to the service it was found on.
  function pathPositions() {
    var X_STEP = 170, ROW = 30, HOST_GAP = 56, NET_GAP = 40;
    var pos = {};
    var nodes = data.graph.nodes.map(function (n) { return n.data; });
    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });
    var edges = data.graph.edges.map(function (e) { return e.data; });

    // Depth of each router: the longest chain of routers from the scanner to it.
    var depth = { scanner: 0 };
    for (var pass = 0; pass < nodes.length; pass++) {
      var changed = false;
      edges.forEach(function (e) {
        var to = byId[e.target];
        if (!to || to.kind !== "router" || depth[e.source] === undefined) return;
        var d = depth[e.source] + 1;
        if (depth[e.target] === undefined || d > depth[e.target]) {
          depth[e.target] = d;
          changed = true;
        }
      });
      if (!changed) break; // a routing loop cannot make this run forever
    }

    // Networks (and hosts outside any network), stacked top to bottom.
    var netX = 0;
    Object.keys(depth).forEach(function (id) { netX = Math.max(netX, depth[id]); });
    netX = (netX + 1) * X_STEP + 60;
    var y = 0;
    var groups = nodes.filter(function (n) {
      return n.kind === "network" || (n.kind === "host" && !n.parent);
    });
    groups.forEach(function (group) {
      var hosts = group.kind === "host" ? [group] : nodes.filter(function (n) {
        return n.kind === "host" && n.parent === group.id;
      });
      hosts.forEach(function (host) {
        var services = nodes.filter(function (n) {
          return n.kind === "service" && n.parent === host.id;
        });
        var findings = nodes.filter(function (n) {
          return n.kind === "finding" && n.parent === host.id;
        });
        if (!services.length && !findings.length) {
          pos[host.id] = { x: netX, y: y };
          y += ROW + HOST_GAP;
          return;
        }
        var row = 0;
        services.forEach(function (svc) {
          pos[svc.id] = { x: netX, y: y + row * ROW };
          var on = findings.filter(function (f) {
            return edges.some(function (e) { return e.source === svc.id && e.target === f.id; });
          });
          on.forEach(function (f, i) { pos[f.id] = { x: netX + 200, y: y + (row + i) * ROW }; });
          row += Math.max(1, on.length);
        });
        findings.forEach(function (f) {
          if (!pos[f.id]) { pos[f.id] = { x: netX + 200, y: y + row * ROW }; row += 1; }
        });
        y += row * ROW + HOST_GAP;
      });
      y += NET_GAP;
    });

    // The scanner and the routers sit level with the middle of everything else.
    var middle = Math.max(0, y - HOST_GAP - NET_GAP) / 2;
    var layers = {};
    Object.keys(depth).forEach(function (id) {
      (layers[depth[id]] = layers[depth[id]] || []).push(id);
    });
    Object.keys(layers).forEach(function (d) {
      var ids = layers[d];
      ids.forEach(function (id, i) {
        pos[id] = { x: Number(d) * X_STEP, y: middle + (i - (ids.length - 1) / 2) * 80 };
      });
    });
    return pos;
  }

  function layoutOptions(name) {
    var common = { name: name, animate: false, fit: true, padding: 30,
      nodeDimensionsIncludeLabels: true };
    if (name === "path") {
      var positions = pathPositions();
      return { name: "preset", fit: true, padding: 30,
        positions: function (node) { return positions[node.id()]; } };
    }
    if (name === "cose") {
      common.randomize = true;
      common.nodeRepulsion = function () { return 12000; };
      common.idealEdgeLength = function () { return 60; };
      common.componentSpacing = 60;
      common.nestingFactor = 1.2;
      common.numIter = 2500;
    } else if (name === "concentric") {
      var depth = { scanner: 5, router: 4, network: 3, host: 2, service: 1, finding: 0 };
      common.concentric = function (n) { return depth[n.data("kind")] || 0; };
      common.levelWidth = function () { return 1; };
    }
    return common;
  }

  function relayout() {
    if (!cy) return;
    cy.layout(layoutOptions(document.getElementById("layout").value)).run();
  }

  function toggle(kind, show) {
    if (!cy) return;
    cy.nodes('[kind = "' + kind + '"]').style("display", show ? "element" : "none");
  }

  function renderLegend() {
    var legend = document.getElementById("legend");
    SEVERITIES.concat(["none"]).forEach(function (sev) {
      var dot = el("span", { class: "dot" });
      dot.style.backgroundColor = sevColor(sev);
      legend.appendChild(el("span", null, dot, sev === "none" ? "no finding" : sev));
    });
  }

  /* --- details panel ------------------------------------------------------------ */

  var details = document.getElementById("details");

  function kv(pairs) {
    var dl = el("dl", { class: "kv" });
    pairs.forEach(function (p) {
      if (p[1] === null || p[1] === undefined || p[1] === "") return;
      dl.appendChild(el("dt", null, p[0]));
      dl.appendChild(el("dd", { class: p[2] || null }, p[1]));
    });
    return dl;
  }

  function showOverview() {
    clear(details);
    details.appendChild(el("div", { class: "kind" }, "map"));
    details.appendChild(el("h3", null, "Click any node"));
    details.appendChild(el("p", { class: "muted" },
      "Hosts, services, findings and routers show their details here. " +
      "Scroll to zoom, drag to move."));
    var s = data.summary;
    details.appendChild(kv([
      ["hosts", s.hosts], ["services", s.services], ["findings", s.findings],
      ["traced", s.traced_hosts + " of " + s.hosts + " hosts"]
    ]));
  }

  function showDetails(node) {
    var d = node.data();
    var ref = d.ref || {};
    var host = ref.host !== undefined ? data.hosts[ref.host] : null;
    clear(details);
    details.appendChild(el("div", { class: "kind" }, d.kind));
    if (d.kind === "finding" && host) {
      var f = host.findings[ref.finding];
      details.appendChild(el("h3", null, f.title));
      details.appendChild(kv([
        ["severity", sevBadge(f.severity)], ["CVE", f.cve], ["rule", f.rule_id],
        ["host", host.host + (host.ip && host.ip !== host.host ? " (" + host.ip + ")" : "")],
        ["port", f.port !== null ? f.port + "/" + f.protocol : null],
        ["fingerprint", f.fingerprint, "mono"]
      ]));
      if (f.description) details.appendChild(el("p", null, f.description));
      if (f.evidence) {
        details.appendChild(el("div", { class: "kind" }, "evidence"));
        details.appendChild(el("pre", null, f.evidence));
      }
    } else if (d.kind === "service" && host) {
      var svc = host.services[ref.service];
      details.appendChild(el("h3", null, service(svc) + " " + (svc.name || "")));
      details.appendChild(kv([
        ["host", host.host], ["state", svc.state], ["product", svc.product],
        ["version", svc.version], ["cpe", svc.cpe, "mono"], ["banner", svc.banner, "mono"]
      ]));
      var onIt = host.findings.filter(function (x) {
        return x.port === svc.port && x.protocol === svc.protocol;
      });
      details.appendChild(el("p", { class: "muted" },
        onIt.length ? onIt.length + " finding(s) on this port" : "No finding on this port."));
    } else if (d.kind === "host" && host) {
      details.appendChild(el("h3", null, host.host));
      details.appendChild(kv([
        ["address", host.ip], ["open ports", host.services.length],
        ["findings", host.findings.length],
        ["route", host.route.length ? host.route.map(function (h) { return h.ip || "?"; })
          .join(" → ") : "not traced", "mono"]
      ]));
      if (host.services.length) {
        var ul = el("ul");
        host.services.forEach(function (x) {
          ul.appendChild(el("li", null, service(x) + "  " + (x.name || "?") + "  " + productLine(x)));
        });
        details.appendChild(ul);
      }
    } else if (d.kind === "router") {
      details.appendChild(el("h3", null, d.id.replace(/^hop:/, "")));
      details.appendChild(kv([["reverse DNS", d.name]]));
      details.appendChild(el("p", { class: "muted" },
        "A router that answered traceroute on the way to a host. It was seen, not scanned: " +
        "no probe was addressed to it."));
    } else if (d.kind === "network") {
      details.appendChild(el("h3", null, d.label));
      details.appendChild(el("p", { class: "muted" },
        node.children().length + " host(s). Grouped by address prefix; the real subnet " +
        "is not visible from outside."));
    } else {
      details.appendChild(el("h3", null, "Scanner"));
      details.appendChild(el("p", { class: "muted" }, "Where the scan was run from."));
    }
  }

  function focus(nodeId) {
    if (!cy) return;
    var node = cy.getElementById(nodeId);
    if (!node || node.empty()) return;
    cy.elements().unselect();
    node.select();
    cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 250 });
    showDetails(node);
    document.getElementById("map").scrollIntoView({ behavior: "smooth", block: "center" });
  }

  /* --- tables ------------------------------------------------------------------- */

  function renderFindings() {
    var table = document.getElementById("findings");
    table.appendChild(el("thead", null, el("tr", null, el("th", null, "Severity"),
      el("th", null, "Host"), el("th", null, "Port"), el("th", null, "Issue"),
      el("th", null, "Evidence"))));
    var rows = [];
    data.hosts.forEach(function (host, h) {
      host.findings.forEach(function (f) { rows.push({ host: host, f: f, h: h }); });
    });
    rows.sort(function (a, b) { return sevRank(a.f.severity) - sevRank(b.f.severity); });
    var body = el("tbody");
    if (!rows.length) {
      body.appendChild(el("tr", null, el("td", { colspan: "5", class: "empty" },
        run.status === "failed" ? "No results: the scan failed." : "No finding.")));
    }
    rows.forEach(function (r) {
      var tr = el("tr", null,
        el("td", null, sevBadge(r.f.severity)),
        el("td", null, r.host.host),
        el("td", { class: "mono" }, r.f.port !== null ? r.f.port + "/" + r.f.protocol : "-"),
        el("td", { class: "wrap" }, r.f.title, r.f.cve ? el("div", { class: "mono muted" }, r.f.cve) : null),
        el("td", { class: "wrap muted" }, r.f.evidence || "-"));
      tr.addEventListener("click", function () { focus("finding:" + r.f.fingerprint); });
      body.appendChild(tr);
    });
    table.appendChild(body);
  }

  function renderHosts() {
    var table = document.getElementById("hosts");
    table.appendChild(el("thead", null, el("tr", null, el("th", null, "Host"),
      el("th", null, "Address"), el("th", null, "Open ports"), el("th", null, "Findings"),
      el("th", null, "Route"))));
    var body = el("tbody");
    if (!data.hosts.length) {
      body.appendChild(el("tr", null, el("td", { colspan: "5", class: "empty" }, "No host.")));
    }
    data.hosts.forEach(function (host) {
      var ports = host.services.map(function (s) {
        return service(s) + " " + (s.name || "?");
      }).join(", ") || "none open";
      var route = host.route.length ? host.route.length + " hops" : "not traced";
      var tr = el("tr", null, el("td", null, host.host), el("td", { class: "mono" }, host.ip || "-"),
        el("td", { class: "wrap" }, ports), el("td", null, host.findings.length),
        el("td", null, route));
      tr.addEventListener("click", function () { focus("host:" + (host.ip || host.host)); });
      body.appendChild(tr);
    });
    table.appendChild(body);
  }

  function settingsLine(settings) {
    if (!settings) return "";
    return Object.keys(settings).filter(function (k) {
      return k !== "name" && settings[k] !== null && settings[k] !== false;
    }).map(function (k) { return k + "=" + settings[k]; }).join(" ");
  }

  function renderRun() {
    var outputs = run.raw_outputs.map(function (o) {
      return o.plugin + " (" + o.format + ", " + o.size + " bytes, sha256 " + o.sha256 + ")";
    });
    var dl = document.getElementById("run");
    var pairs = [
      ["target", run.target], ["status", run.status], ["started", run.started_at],
      ["finished", run.finished_at], ["ReconKit", run.reconkit_version],
      ["profile", run.profile ? run.profile + "  " + settingsLine(run.profile_settings) : null,
        "mono"],
      ["skipped scanners", run.skipped_scanners.join(", ")],
      ["out of scope (dropped)", run.out_of_scope.join(", ")],
      ["raw output kept", outputs.join("\n")]
    ];
    var built = kv(pairs);
    while (built.firstChild) dl.appendChild(built.firstChild);
    document.getElementById("footer").textContent = "Generated " + when(data.generated_at) +
      " by " + data.generated_by + ". Raw scanner output: reconkit raw " + run.id +
      ". This report contains scan results: treat it as confidential.";
  }

  /* --- wire up ------------------------------------------------------------------ */

  renderHeader();
  renderFindings();
  renderHosts();
  renderRun();
  renderLegend();
  buildMap();
  showOverview();

  document.getElementById("layout").addEventListener("change", relayout);
  document.getElementById("fit").addEventListener("click", function () { if (cy) cy.fit(null, 30); });
  document.getElementById("show-services").addEventListener("change", function (e) {
    toggle("service", e.target.checked);
  });
  document.getElementById("show-findings").addEventListener("change", function (e) {
    toggle("finding", e.target.checked);
  });
})();
