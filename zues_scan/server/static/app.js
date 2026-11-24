/* ZuesScan dashboard — plain JavaScript, no build step, no third-party code.

   Everything the API returns may come from a scanned machine (a banner, a title) and
   may be hostile. This script therefore only ever puts data into the page as TEXT
   (textContent / text nodes): never innerHTML, never markup built from strings, never
   eval. The page's CSP allows only this file and app.css, and requests only to this
   server.

   Authentication: the token is sent once to /api/v1/session, which opens a session on
   the server and sets an HttpOnly cookie (the session's secret, not the token) this
   script cannot read. Every request carries the X-ZuesScan header, which the server
   requires (with the cookie) for anything that changes data: CSRF defence. The periodic
   refresh also sends X-ZuesScan-Refresh, so that a tab left open still goes idle. */
(function () {
  "use strict";

  var me = null; // {name, role}
  var timer = null; // the overview's refresh

  var STATUSES = ["new", "open", "fix_claimed", "fake_fix", "reappeared", "accepted", "fixed", "gone"];
  var ACTIONS = {
    claim_fixed: "Claim fixed (the next scan will check)",
    accept: "Accept the risk (reason + review date)",
    reopen: "Reopen",
  };

  /* --- helpers ------------------------------------------------------------------ */

  function $(id) {
    return document.getElementById(id);
  }

  // el("td", {class: "x"}, "text", node, ...) — children are text or nodes.
  function el(tag, attrs) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      var value = attrs[key];
      if (value === null || value === undefined || value === false) return;
      if (key === "on") {
        Object.keys(value).forEach(function (ev) {
          node.addEventListener(ev, value[ev]);
        });
      } else {
        node.setAttribute(key, value === true ? "" : value);
      }
    });
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) {
      child.forEach(function (c) {
        append(node, c);
      });
      return;
    }
    node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function when(iso) {
    // Stored times are ISO 8601 UTC; show them as such, to the minute.
    return iso ? String(iso).slice(0, 16).replace("T", " ") : "-";
  }

  function every(seconds) {
    if (!seconds) return "on request";
    if (seconds % 86400 === 0) return "every " + seconds / 86400 + "d";
    if (seconds % 3600 === 0) return "every " + seconds / 3600 + "h";
    return "every " + Math.round(seconds / 60) + "m";
  }

  function table(headers, rows, empty) {
    var head = el("tr", null, headers.map(function (h) {
      return el("th", { scope: "col" }, h);
    }));
    var body = rows.length
      ? rows
      : [el("tr", null, el("td", { class: "empty", colspan: headers.length }, empty || "Nothing yet."))];
    return el("div", { class: "table-wrap" }, el("table", null, el("thead", null, head), el("tbody", null, body)));
  }

  function prio(p) {
    return el("span", { class: "prio prio-" + p }, p || "-");
  }

  function sev(s) {
    return el("span", { class: "sev sev-" + s }, s);
  }

  function state(s) {
    return el("span", { class: "state state-" + s }, s);
  }

  function status(s) {
    return el("span", { class: "state status-" + s }, String(s).replace("_", " "));
  }

  function flash(text, bad) {
    var box = $("flash");
    box.textContent = text;
    box.className = bad ? "flash bad" : "flash";
    box.hidden = false;
    clearTimeout(flash.timer);
    flash.timer = setTimeout(function () {
      box.hidden = true;
    }, bad ? 9000 : 5000);
  }

  function isOperator() {
    return me && (me.role === "operator" || me.role === "admin"); // an admin is an operator too
  }

  function isAdmin() {
    return me && me.role === "admin";
  }

  /* --- the API ------------------------------------------------------------------ */

  // refresh: a request the page makes by itself (a timer), not the person: it does not
  // keep the session from going idle.
  function api(method, path, body, refresh) {
    var headers = { Accept: "application/json", "X-ZuesScan": "1" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (refresh) headers["X-ZuesScan-Refresh"] = "1";
    return fetch("/api/v1" + path, {
      method: method,
      headers: headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then(function (response) {
      if (response.status === 204) return null;
      return response.json().then(
        function (data) {
          if (response.ok) return data;
          if (response.status === 401 && path !== "/session") showLogin();
          throw new Error(detail(data) || response.status + " " + response.statusText);
        },
        function () {
          throw new Error(response.status + " " + response.statusText);
        }
      );
    });
  }

  function detail(data) {
    if (!data || data.detail === undefined) return null;
    if (typeof data.detail === "string") return data.detail;
    // FastAPI's validation errors: [{loc: [...], msg: "..."}]
    return data.detail
      .map(function (d) {
        return (d.loc || []).slice(1).join(".") + ": " + d.msg;
      })
      .join("; ");
  }

  /* --- sign in / out ------------------------------------------------------------ */

  function showLogin() {
    me = null;
    stopTimer();
    $("app").hidden = true;
    $("login").hidden = false;
    $("token").focus();
  }

  function showApp(who) {
    me = who;
    $("login").hidden = true;
    $("app").hidden = false;
    $("who").textContent = who.name + " (" + who.role + ")";
    document.querySelector('#nav a[data-view="settings"]').hidden = !isAdmin();
    route();
  }

  $("login-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var input = $("token");
    var error = $("login-error");
    error.hidden = true;
    api("POST", "/session", { token: input.value })
      .then(function (who) {
        input.value = "";
        showApp(who);
      })
      .catch(function (err) {
        error.textContent = err.message === "unknown token" ? "That token is not valid." : err.message;
        error.hidden = false;
      });
  });

  $("logout").addEventListener("click", function () {
    api("DELETE", "/session").then(showLogin, showLogin);
  });

  /* --- routing ------------------------------------------------------------------ */

  var VIEWS = {
    overview: overview,
    runs: runs,
    findings: findings,
    finding: finding,
    audit: audit,
    settings: settings,
  };

  function route() {
    if (!me) return;
    stopTimer();
    var parts = (location.hash || "#/overview").slice(2).split("/");
    var name = parts[0] || "overview";
    if (name === "findings" && parts[1]) name = "finding";
    if (!VIEWS[name] || (name === "settings" && !isAdmin())) name = "overview";
    Array.prototype.forEach.call(document.querySelectorAll("#nav a"), function (a) {
      var active = a.getAttribute("data-view") === (name === "finding" ? "findings" : name);
      a.className = active ? "active" : "";
      if (active) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    // Each visit draws into its own element: a slow answer for the page left behind then
    // lands in a detached node, instead of over the page now shown.
    var view = $("view");
    clear(view);
    var page = el("div");
    view.appendChild(page);
    page.appendChild(el("p", { class: "muted" }, "Loading…"));
    VIEWS[name](page, parts.slice(1)).catch(function (err) {
      clear(page);
      page.appendChild(el("p", { class: "error" }, "Could not load: " + err.message));
    });
  }

  window.addEventListener("hashchange", route);

  function stopTimer() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  /* --- overview: targets, jobs, what needs attention ---------------------------- */

  function overview(view) {
    return Promise.all([api("GET", "/targets"), api("GET", "/jobs"), api("GET", "/findings")]).then(
      function (results) {
        var targets = results[0];
        var active = results[2];
        clear(view);
        view.appendChild(el("h1", null, "Overview"));
        view.appendChild(tiles(active));
        view.appendChild(el("h2", null, "Targets"));
        view.appendChild(
          el("p", { class: "muted small" }, "Only the targets listed in service.toml can be scanned.")
        );
        view.appendChild(targetTable(targets));
        view.appendChild(el("h2", null, "Scan jobs"));
        var jobsBox = el("div");
        view.appendChild(jobsBox);
        drawJobs(jobsBox, results[1]);
        timer = setInterval(function () {
          api("GET", "/jobs", undefined, true).then(function (jobs) {
            drawJobs(jobsBox, jobs);
          }, function () {});
        }, 5000);
      }
    );
  }

  function tiles(active) {
    var counts = { P1: 0, P2: 0, P3: 0, P4: 0 };
    var alerts = 0;
    active.forEach(function (f) {
      counts[f.priority] = (counts[f.priority] || 0) + 1;
      if (f.status === "fake_fix" || f.status === "reappeared") alerts++;
    });
    var box = el("div", { class: "tiles" });
    ["P1", "P2", "P3", "P4"].forEach(function (p) {
      box.appendChild(
        el("a", { class: "tile", href: "#/findings" }, el("span", { class: "n prio-" + p }, counts[p]), el("span", { class: "l" }, p + " active"))
      );
    });
    box.appendChild(
      el("a", { class: "tile", href: "#/findings" }, el("span", { class: "n prio-P1" }, alerts), el("span", { class: "l" }, "fake fixes / reappeared"))
    );
    return box;
  }

  function targetTable(targets) {
    var rows = targets.map(function (t) {
      var flags = [t.nuclei ? "nuclei" : null, t.discover ? "subdomains" : null, t.authenticated ? "authenticated" : null]
        .filter(Boolean)
        .join(", ");
      var action = isOperator()
        ? el("button", { type: "button", class: "primary", on: { click: function (e) { scan(t.name, e.target); } } }, "Scan now")
        : el("span", { class: "muted small" }, "operator only");
      return el(
        "tr",
        null,
        el("td", null, el("strong", null, t.name)),
        el("td", { class: "mono" }, t.target),
        el("td", null, t.profile),
        el("td", null, every(t.every_seconds)),
        el("td", { class: "nowrap" }, when(t.last_started_at)),
        el("td", null, t.engagement || "-"),
        el("td", null, flags || "-"),
        el("td", null, action)
      );
    });
    return table(["Name", "Target", "Profile", "Schedule", "Last scan (UTC)", "Engagement", "Checks", ""], rows, "No target yet: an admin adds them in Settings.");
  }

  function scan(name, button) {
    button.disabled = true;
    api("POST", "/scans", { target: name })
      .then(function (data) {
        flash("Scan of " + name + " queued (job " + data.job.id.slice(0, 8) + ").");
        route();
      })
      .catch(function (err) {
        flash("Could not queue the scan: " + err.message, true);
        button.disabled = false;
      });
  }

  function drawJobs(box, jobs) {
    var rows = jobs.map(function (j) {
      var outcome;
      if (j.result && j.result.run_id) {
        outcome = el("a", { href: "/api/v1/runs/" + j.result.run_id + "/report.html", target: "_blank", rel: "noopener" }, "run #" + j.result.run_id);
      } else if (j.result) {
        outcome = el("span", { class: "error" }, (j.result.messages || []).join(" ") || "exit " + j.result.code);
      } else {
        outcome = j.error ? el("span", { class: "error" }, j.error) : "-";
      }
      return el(
        "tr",
        null,
        el("td", { class: "nowrap" }, when(j.enqueued_at)),
        el("td", null, j.target || "?"),
        el("td", null, j.operator || "?"),
        el("td", null, state(j.status)),
        el("td", null, j.result && j.result.alerts ? String(j.result.alerts) : "-"),
        el("td", { class: "wrap" }, outcome)
      );
    });
    clear(box);
    box.appendChild(table(["Queued (UTC)", "Target", "By", "State", "Alerts", "Result"], rows, "No scan job yet."));
  }

  /* --- runs --------------------------------------------------------------------- */

  function runs(view) {
    return api("GET", "/runs").then(function (list) {
      clear(view);
      view.appendChild(el("h1", null, "Runs"));
      view.appendChild(
        el("p", { class: "muted small" }, "The report opens the attack-surface map in a new tab: the same self-contained page as zues report --html.")
      );
      var rows = list.map(function (r) {
        var base = "/api/v1/runs/" + r.id;
        return el(
          "tr",
          null,
          el("td", null, "#" + r.id),
          el("td", { class: "nowrap" }, when(r.started_at)),
          el("td", null, state(r.status)),
          el("td", { class: "mono" }, r.target),
          el("td", null, String(r.hosts)),
          el("td", null, String(r.services)),
          el("td", null, String(r.findings)),
          el(
            "td",
            { class: "nowrap" },
            el("a", { href: base + "/report.html", target: "_blank", rel: "noopener" }, "Map & report"),
            " · ",
            el("a", { href: base, target: "_blank", rel: "noopener" }, "JSON"),
            " · ",
            el("a", { href: base + "/sarif" }, "SARIF")
          )
        );
      });
      view.appendChild(table(["Run", "Started (UTC)", "Status", "Target", "Hosts", "Services", "Findings", ""], rows, "No run stored yet."));
    });
  }

  /* --- findings ----------------------------------------------------------------- */

  function findings(view) {
    var filter = sessionFilter();
    var query = filter === "active" ? "" : filter === "all" ? "?all=true" : "?status=" + encodeURIComponent(filter);
    return api("GET", "/findings" + query).then(function (list) {
      clear(view);
      view.appendChild(el("h1", null, "Findings"));
      var select = el(
        "select",
        { id: "filter", on: { change: function (e) { sessionFilter(e.target.value); route(); } } },
        el("option", { value: "active" }, "Active (needs attention)"),
        el("option", { value: "all" }, "All"),
        STATUSES.map(function (s) {
          return el("option", { value: s }, s.replace("_", " "));
        })
      );
      select.value = filter;
      view.appendChild(el("div", { class: "toolbar" }, el("label", null, "Show ", select), el("span", { class: "muted small" }, list.length + " finding(s), most urgent first")));
      var rows = list.map(function (f) {
        var where = f.host + (f.port ? ":" + f.port + "/" + (f.protocol || "tcp") : "");
        return el(
          "tr",
          {
            class: "click",
            tabindex: "0",
            on: {
              click: function () { location.hash = "#/findings/" + f.id; },
              keydown: function (e) { if (e.key === "Enter") location.hash = "#/findings/" + f.id; },
            },
          },
          el("td", null, "#" + f.id),
          el("td", null, prio(f.priority)),
          el("td", null, sev(f.severity)),
          el("td", { class: "wrap" }, f.title, f.cve ? el("div", { class: "muted small mono" }, f.cve) : null),
          el("td", { class: "mono" }, where),
          el("td", null, status(f.status)),
          el("td", { class: "nowrap" }, when(f.last_seen))
        );
      });
      view.appendChild(table(["#", "Priority", "Severity", "Finding", "Where", "Status", "Last seen (UTC)"], rows, "No finding with that status."));
    });
  }

  function sessionFilter(value) {
    try {
      if (value) sessionStorage.setItem("zues-filter", value);
      return sessionStorage.getItem("zues-filter") || "active";
    } catch (e) {
      return value || "active";
    }
  }

  function finding(view, parts) {
    var id = parseInt(parts[0], 10);
    if (!(id > 0)) return Promise.reject(new Error("no such finding"));
    return api("GET", "/findings/" + id).then(function (f) {
      clear(view);
      view.appendChild(el("p", null, el("a", { href: "#/findings" }, "← Findings")));
      view.appendChild(el("h1", null, "#" + f.id + " " + f.title));
      var facts = [
        ["Status", status(f.status)],
        ["Priority", [prio(f.priority), " ", f.priority_reason]],
        ["Severity", sev(f.severity)],
        ["CVE / rule", f.cve || f.rule_id || "-"],
        ["Confidence", f.confidence || "-"],
        ["CVSS", f.cvss_score === null ? "-" : String(f.cvss_score)],
        ["EPSS", f.epss === null ? "-" : (f.epss * 100).toFixed(1) + "%"],
        ["Known exploited", f.kev_added ? "CISA KEV since " + f.kev_added : "no"],
        ["Host", f.host + (f.ip && f.ip !== f.host ? " (" + f.ip + ")" : "")],
        ["Port", f.port ? f.port + "/" + (f.protocol || "tcp") : "-"],
        ["First seen", when(f.first_seen) + " UTC"],
        ["Last seen", when(f.last_seen) + " UTC"],
        ["Accepted until", f.accepted_until || "-"],
        ["Note", f.note || "-"],
        ["Fingerprint", el("span", { class: "mono small" }, f.fingerprint)],
      ];
      view.appendChild(
        el("div", { class: "panel" }, el("dl", { class: "kv" }, facts.map(function (kv) {
          return [el("dt", null, kv[0]), el("dd", null, kv[1])];
        })))
      );
      view.appendChild(el("h2", null, "History"));
      view.appendChild(
        el("div", { class: "panel" }, el("ol", { class: "history" }, f.history.map(function (e) {
          return el(
            "li",
            null,
            when(e.at) + " UTC — " + e.event.replace("_", " ") + (e.old_status ? " (" + e.old_status + " → " + e.new_status + ")" : " (" + e.new_status + ")"),
            e.run_id ? " in run #" + e.run_id : "",
            e.actor ? " by " + e.actor : "",
            e.note ? el("div", { class: "muted small" }, e.note) : null
          );
        })))
      );
      if (isOperator()) view.appendChild(decisionForm(f));
    });
  }

  function decisionForm(f) {
    var action = el("select", { id: "action" }, Object.keys(ACTIONS).map(function (a) {
      return el("option", { value: a }, ACTIONS[a]);
    }));
    var note = el("textarea", { id: "note", maxlength: "2000" });
    var until = el("input", { id: "until", type: "date" });
    var untilRow = el("label", null, "Review date (accept only)", until);
    var button = el("button", { type: "submit", class: "primary" }, "Record decision");
    function sync() {
      untilRow.hidden = action.value !== "accept";
    }
    action.addEventListener("change", sync);
    sync();
    var form = el(
      "form",
      { class: "decision panel" },
      el("label", null, "Decision", action),
      el("label", null, "Note / reason (recorded in the audit trail)", note),
      untilRow,
      el("div", null, button)
    );
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      button.disabled = true;
      var body = { action: action.value, note: note.value.trim() || null };
      if (action.value === "accept") body.until = until.value || null;
      api("POST", "/findings/" + f.id + "/decision", body)
        .then(function (data) {
          flash("Finding #" + f.id + " is now " + data.status.replace("_", " ") + ".");
          route();
        })
        .catch(function (err) {
          flash(err.message, true);
          button.disabled = false;
        });
    });
    return el("div", null, el("h2", null, "Decide"), form);
  }

  /* --- settings (admin): what to scan, how, and who may --------------------------- */

  var NEW_SCOPE = [
    "# One entry per line: an address, a range (CIDR), a name, or *.domain for the names under it.",
    "# A line starting with ! is denied, even inside an allowed range.",
    "@engagement ACME-2026-01            # the contract or ticket that authorises the scans",
    "@expires 2026-12-31 +07:00          # no scan after this day",
    "# @window Mon-Fri 08:00-18:00 +07:00  # only during these hours",
    "# @activity active                  # needed for nuclei (active checks); default: scan",
    "10.0.0.0/24",
    "!10.0.0.1",
    "",
  ].join("\n");

  // For the pattern attribute, which browsers compile with the "v" flag: "-" in a class
  // must be escaped there (the attribute holds a backslash, hence two in this string).
  var NAME_PATTERN = "[a-z0-9][a-z0-9_\\-]*";

  var KINDS = [
    ["scanners", "scanner", "Scanners", "find hosts and open ports (default: nmap)"],
    ["checks", "check", "Checks", "test what the scanners found"],
    ["discoverers", "discovery", "Discovery", "find names under a domain first (the target is then a domain)"],
  ];

  // A list of cells (text or nodes) as a table row, for table().
  function row(cells) {
    return el("tr", null, cells.map(function (c) { return el("td", null, c); }));
  }

  function settings(view, parts) {
    return api("GET", "/admin/config").then(function (cfg) {
      clear(view);
      if (parts[0] === "scope") return scopeEditor(view, cfg, decodeURIComponent(parts[1] || ""));
      if (parts[0] === "target") return targetEditor(view, cfg, decodeURIComponent(parts[1] || ""));
      view.appendChild(el("h1", null, "Settings"));
      view.appendChild(el("p", { class: "muted" },
        "What to scan, how, and who may. Changes apply at once and each one is recorded in the " +
        "audit trail. Entries from service.toml are shown but can only be changed in that file."));
      if (cfg.problems.length) {
        view.appendChild(el("div", { class: "panel error" }, el("strong", null, "Left out: "),
          el("ul", null, cfg.problems.map(function (p) { return el("li", null, p); }))));
      }
      view.appendChild(settingsTargets(cfg));
      view.appendChild(settingsScopes(cfg));
      view.appendChild(settingsTokens(cfg));
      view.appendChild(settingsSessions(cfg));
    });
  }

  function source(s) {
    return s === "dashboard" ? el("span", { class: "state state-finished" }, "dashboard")
      : el("span", { class: "state" }, "service.toml");
  }

  function settingsTargets(cfg) {
    var ownScopes = cfg.scopes.filter(function (s) { return s.source === "dashboard"; });
    var add = el("button", {
      type: "button", class: "primary", disabled: ownScopes.length ? null : true,
      on: { click: function () { location.hash = "#/settings/target/new"; } },
    }, "Add target");
    var rows = cfg.targets.map(function (t) {
      var tools = [].concat(t.scanners, t.checks, t.discoverers).join(", ");
      return [
        el("strong", null, t.name),
        el("span", { class: "mono" }, t.target),
        t.scope || el("span", { class: "muted" }, "(file)"),
        t.profile,
        t.every || el("span", { class: "muted" }, "on demand"),
        tools,
        source(t.source),
        t.source === "dashboard" ? el("a", { href: "#/settings/target/" + encodeURIComponent(t.name) }, "Edit") : "",
      ];
    });
    return el("section", null,
      el("div", { class: "toolbar" }, el("h2", null, "Targets"), add,
        ownScopes.length ? null : el("span", { class: "muted small" }, "Add a scope first: a target needs one.")),
      table(["Name", "Target", "Scope", "Profile", "Schedule", "Tools", "Source", ""], rows.map(row), "No target yet."));
  }

  function settingsScopes(cfg) {
    var add = el("button", {
      type: "button", class: "primary",
      on: { click: function () { location.hash = "#/settings/scope/new"; } },
    }, "Add scope");
    var rows = cfg.scopes.map(function (s) {
      var own = s.source === "dashboard";
      return [
        el("strong", { class: own ? null : "mono" }, s.name),
        own ? (s.error ? el("span", { class: "error" }, s.error)
          : el("span", { class: "mono small" }, s.allow.slice(0, 4).join(", ") + (s.allow.length > 4 ? " …" : "")))
          : el("span", { class: "muted" }, "a file on the server"),
        own ? s.activity : "",
        own ? (s.expires ? when(s.expires) : el("span", { class: "muted" }, "never")) : "",
        s.used_by.join(", ") || el("span", { class: "muted" }, "unused"),
        source(s.source),
        own ? el("a", { href: "#/settings/scope/" + encodeURIComponent(s.name) }, "Edit") : "",
      ];
    });
    return el("section", null,
      el("div", { class: "toolbar" }, el("h2", null, "Scopes (authorisations)"), add),
      table(["Name", "Allows", "@activity", "Expires", "Used by", "Source", ""], rows.map(row), "No scope yet."));
  }

  function settingsTokens(cfg) {
    var rows = cfg.tokens.map(function (t) {
      var remove = t.source === "dashboard" && !t.you ? el("button", {
        type: "button", class: "link",
        on: { click: function () { removeToken(t.name); } },
      }, "Revoke") : "";
      return [el("strong", null, t.name), t.role, source(t.source), t.you ? "you" : "", remove];
    });
    var name = el("input", { id: "token-name", maxlength: "64", required: true, placeholder: "who it is for" });
    var role = el("select", { id: "token-role" }, ["viewer", "operator", "admin"].map(function (r) {
      return el("option", { value: r }, r);
    }));
    var shown = el("div", { class: "panel", hidden: true });
    var button = el("button", { type: "submit", class: "primary" }, "Create token");
    var form = el("form", { class: "toolbar" },
      el("label", null, "Name ", name), el("label", null, "Role ", role), button);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      button.disabled = true;
      api("POST", "/admin/tokens", { name: name.value.trim(), role: role.value })
        .then(function (made) {
          clear(shown);
          append(shown, [
            el("strong", null, "Token for " + made.name + " (" + made.role + "): copy it now, it is shown only once."),
            el("pre", { class: "mono" }, made.token),
            el("button", { type: "button", on: { click: function () { route(); } } }, "Done"),
          ]);
          shown.hidden = false;
          name.value = "";
          button.disabled = false;
        })
        .catch(function (err) {
          flash(err.message, true);
          button.disabled = false;
        });
    });
    return el("section", null, el("h2", null, "Tokens (who may sign in)"),
      table(["Name", "Role", "Source", "", ""], rows.map(row), "No token."),
      el("p", { class: "muted small" },
        "viewer: reads; operator: also scans and records decisions; admin: also changes these settings."),
      form, shown);
  }

  function settingsSessions(cfg) {
    var rows = cfg.sessions.map(function (s) {
      var end = s.you ? el("span", { class: "muted" }, "this browser") : el("button", {
        type: "button", class: "link",
        on: { click: function () { endSession(s); } },
      }, "End");
      return [
        el("strong", null, s.name), s.role, el("span", { class: "mono" }, s.client || "-"),
        when(s.created_at), when(s.last_seen_at), when(s.idle_until), end,
      ];
    });
    return el("section", null, el("h2", null, "Sessions (signed in now)"),
      table(["Name", "Role", "From", "Signed in", "Last active", "Ends if idle until", ""],
        rows.map(row), "Nobody is signed in with a browser."),
      el("p", { class: "muted small" },
        "A session ends when its owner signs out, after 30 minutes without use, 8 hours after " +
        "signing in, when its token is revoked, or here. Tokens used by scripts (Bearer) have " +
        "no session: revoke the token to stop them."));
  }

  function endSession(s) {
    api("DELETE", "/admin/sessions/" + s.id)
      .then(function () { flash("Session of " + s.name + " ended."); route(); })
      .catch(function (err) { flash(err.message, true); });
  }

  function removeToken(name) {
    api("DELETE", "/admin/tokens/" + encodeURIComponent(name))
      .then(function () { flash("Token " + name + " revoked."); route(); })
      .catch(function (err) { flash(err.message, true); });
  }

  function saved(what, result) {
    var text = what + " saved.";
    if (result && result.warnings && result.warnings.length) {
      flash(text + " Note: " + result.warnings.join(" "), true);
    } else {
      flash(text);
    }
    location.hash = "#/settings";
  }

  function removeButton(path, what) {
    return el("button", {
      type: "button",
      on: { click: function () {
        api("DELETE", path).then(function () { flash(what + " deleted."); location.hash = "#/settings"; })
          .catch(function (err) { flash(err.message, true); });
      } },
    }, "Delete");
  }

  function scopeEditor(view, cfg, name) {
    var isNew = name === "new";
    var existing = cfg.scopes.filter(function (s) { return s.source === "dashboard" && s.name === name; })[0];
    if (!isNew && !existing) throw new Error("no dashboard scope named " + name);
    var nameInput = el("input", { id: "scope-name", maxlength: "64", required: true, pattern: NAME_PATTERN,
      placeholder: "e.g. office-lan" });
    var text = el("textarea", { id: "scope-text", class: "mono", rows: "16", spellcheck: "false" });
    text.value = isNew ? NEW_SCOPE : existing.text;
    var button = el("button", { type: "submit", class: "primary" }, "Save scope");
    var form = el("form", { class: "decision panel" },
      isNew ? el("label", null, "Name (lowercase letters, digits, - and _)", nameInput)
        : el("p", null, "Scope ", el("strong", null, name), existing.used_by.length
          ? " — used by " + existing.used_by.join(", ") : ""),
      el("label", null, "Authorisation: what may be scanned, until when, how far", text),
      el("p", { class: "muted small" },
        "Directives: @engagement <reference>, @expires <YYYY-MM-DD> [+HH:MM], " +
        "@window [Mon-Fri|daily] HH:MM-HH:MM [+HH:MM], @activity passive|scan|active. " +
        "Only scan what you own or are authorised in writing to test."),
      el("div", { class: "toolbar" }, button, isNew ? null : removeButton("/admin/scopes/" + encodeURIComponent(name), "Scope " + name),
        el("a", { href: "#/settings" }, "Cancel")));
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var target = isNew ? nameInput.value.trim() : name;
      button.disabled = true;
      api("PUT", "/admin/scopes/" + encodeURIComponent(target), { text: text.value })
        .then(function (result) { saved("Scope " + target, result); })
        .catch(function (err) { flash(err.message, true); button.disabled = false; });
    });
    view.appendChild(el("p", null, el("a", { href: "#/settings" }, "← Settings")));
    view.appendChild(el("h1", null, isNew ? "New scope" : "Scope " + name));
    view.appendChild(form);
  }

  function targetEditor(view, cfg, name) {
    var isNew = name === "new";
    var t = cfg.targets.filter(function (x) { return x.source === "dashboard" && x.name === name; })[0];
    if (!isNew && !t) throw new Error("no dashboard target named " + name);
    t = t || { target: "", scope: null, profile: "standard", every: null, engagement: null,
      scanners: ["nmap"], checks: [], discoverers: [], discover_limit: null, ipv4_only: false };
    var scopes = cfg.scopes.filter(function (s) { return s.source === "dashboard"; });
    var nameInput = el("input", { id: "target-name", maxlength: "64", required: true, pattern: NAME_PATTERN,
      placeholder: "e.g. office-lan" });
    var address = el("input", { id: "target-address", maxlength: "253", required: true, value: t.target,
      placeholder: "10.0.0.0/24, 203.0.113.7, app.example.com or example.com (discovery)" });
    var scope = el("select", { id: "target-scope", required: true }, scopes.map(function (s) {
      return el("option", { value: s.name, selected: s.name === t.scope ? true : null }, s.name + " (@activity " + s.activity + ")");
    }));
    var profile = el("select", { id: "target-profile" }, cfg.profiles.map(function (p) {
      return el("option", { value: p.name, selected: p.name === t.profile ? true : null }, p.name + " — " + p.description);
    }));
    var every = el("input", { id: "target-every", maxlength: "16", value: t.every || "", placeholder: "e.g. 24h — empty: only when asked" });
    var engagement = el("input", { id: "target-engagement", maxlength: "200", value: t.engagement || "" });
    var limit = el("input", { id: "target-limit", type: "number", min: "1", max: "100000", value: t.discover_limit || "" });
    var ipv4 = el("input", { id: "target-ipv4", type: "checkbox", checked: t.ipv4_only ? true : null });
    var boxes = {};
    var groups = KINDS.map(function (k) {
      boxes[k[0]] = [];
      var plugins = cfg.plugins.filter(function (p) { return p.kind === k[1]; });
      return el("fieldset", { class: "panel" }, el("legend", null, k[2] + " — " + k[3]),
        plugins.map(function (p) {
          var box = el("input", { type: "checkbox", value: p.name, checked: t[k[0]].indexOf(p.name) >= 0 ? true : null });
          boxes[k[0]].push(box);
          return el("label", { class: "plugin" }, box, " ", el("strong", null, p.name), " ",
            el("span", { class: "state" }, p.activity), " ", el("span", { class: "muted" }, p.summary),
            p.ready ? null : el("span", { class: "error small" }, " — not installed on the server"));
        }));
    });
    var button = el("button", { type: "submit", class: "primary" }, "Save target");
    var form = el("form", { class: "decision panel settings-form" },
      isNew ? el("label", null, "Name (lowercase letters, digits, - and _)", nameInput) : null,
      el("label", null, "Target", address),
      el("label", null, "Scope (the authorisation it is checked against)", scope),
      el("label", null, "Profile", profile),
      el("label", null, "Schedule", every),
      el("label", null, "Engagement (recorded with every run)", engagement),
      groups,
      el("label", null, "Names considered at most, with discovery (default 1000)", limit),
      el("label", { class: "plugin" }, ipv4, " IPv4 only (do not look up IPv6 addresses)"),
      el("p", { class: "muted small" },
        "Checked before it is saved: the target must be inside the scope, and no tool may go " +
        "beyond the scope's @activity (nuclei needs @activity active)."),
      el("div", { class: "toolbar" }, button, isNew ? null : removeButton("/admin/targets/" + encodeURIComponent(name), "Target " + name),
        el("a", { href: "#/settings" }, "Cancel")));
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var target = isNew ? nameInput.value.trim() : name;
      var body = {
        target: address.value.trim(), scope: scope.value, profile: profile.value,
        every: every.value.trim() || null, engagement: engagement.value.trim() || null,
        discover_limit: limit.value ? parseInt(limit.value, 10) : null, ipv4_only: ipv4.checked,
      };
      KINDS.forEach(function (k) {
        body[k[0]] = boxes[k[0]].filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
      });
      button.disabled = true;
      api("PUT", "/admin/targets/" + encodeURIComponent(target), body)
        .then(function (result) { saved("Target " + target, result); })
        .catch(function (err) { flash(err.message, true); button.disabled = false; });
    });
    view.appendChild(el("p", null, el("a", { href: "#/settings" }, "← Settings")));
    view.appendChild(el("h1", null, isNew ? "New target" : "Target " + name));
    view.appendChild(form);
  }

  /* --- audit -------------------------------------------------------------------- */

  function audit(view) {
    return api("GET", "/audit").then(function (data) {
      clear(view);
      view.appendChild(el("h1", null, "Audit trail"));
      var chain = data.chain;
      if (!chain) {
        view.appendChild(el("p", { class: "muted" }, "Nothing recorded yet."));
        return;
      }
      if (chain.intact) {
        view.appendChild(
          el(
            "div",
            { class: "chain ok" },
            el("strong", null, "Chain intact"),
            " — " + chain.events + " event(s), every scan's evidence matches what was recorded. Head: ",
            el("span", { class: "mono small" }, chain.head),
            el("div", { class: "muted small" }, "Keep the head hash outside this server to detect a rewritten history.")
          )
        );
      } else {
        view.appendChild(
          el("div", { class: "chain broken" }, el("strong", null, "Chain BROKEN"), el("ul", null, chain.problems.map(function (p) {
            return el("li", null, p);
          })))
        );
      }
      var rows = data.events.map(function (e) {
        var d = e.detail || {};
        var what = {
          scan: "run #" + d.run_id + " " + (d.status || ""),
          refused: "refused: " + (d.reason || ""),
          deleted: "deleted run #" + d.run_id,
          finding: "finding #" + d.finding_id + ": " + (d.action || "") + " (" + (d.from || "") + " → " + (d.to || "") + ")",
          config: d.action || "config",
          auth: (d.action || "auth") + (d.session ? " (session #" + d.session + ")" : "") +
            (d.failures ? " after " + d.failures + " failed sign-ins" : "") +
            (d.client ? " from " + d.client : ""),
        }[e.kind] || e.kind;
        return el(
          "tr",
          null,
          el("td", null, "#" + e.id),
          el("td", { class: "nowrap" }, when(e.at)),
          el("td", null, e.kind),
          el("td", null, e.operator || "?"),
          el("td", null, e.engagement || "-"),
          el("td", { class: "mono" }, e.target),
          el("td", { class: "wrap" }, what)
        );
      });
      view.appendChild(el("h2", null, "Latest events"));
      view.appendChild(table(["#", "At (UTC)", "Kind", "By", "Engagement", "Target", "What"], rows));
    });
  }

  /* --- start -------------------------------------------------------------------- */

  api("GET", "/me").then(showApp, showLogin);
})();
