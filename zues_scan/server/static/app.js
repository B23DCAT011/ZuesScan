/* ZuesScan dashboard — plain JavaScript, no build step, no third-party code.

   Everything the API returns may come from a scanned machine (a banner, a title) and
   may be hostile. This script therefore only ever puts data into the page as TEXT
   (textContent / text nodes): never innerHTML, never markup built from strings, never
   eval. The page's CSP allows only this file and app.css, and requests only to this
   server.

   Authentication: the token is sent once to /api/v1/session, which sets an HttpOnly
   cookie this script cannot read. Every request carries the X-ZuesScan header, which
   the server requires (with the cookie) for anything that changes data: CSRF defence. */
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
    return me && me.role === "operator";
  }

  /* --- the API ------------------------------------------------------------------ */

  function api(method, path, body) {
    var headers = { Accept: "application/json", "X-ZuesScan": "1" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
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
  };

  function route() {
    if (!me) return;
    stopTimer();
    var parts = (location.hash || "#/overview").slice(2).split("/");
    var name = parts[0] || "overview";
    if (name === "findings" && parts[1]) name = "finding";
    if (!VIEWS[name]) name = "overview";
    Array.prototype.forEach.call(document.querySelectorAll("#nav a"), function (a) {
      var active = a.getAttribute("data-view") === (name === "finding" ? "findings" : name);
      a.className = active ? "active" : "";
      if (active) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    var view = $("view");
    clear(view);
    view.appendChild(el("p", { class: "muted" }, "Loading…"));
    VIEWS[name](view, parts.slice(1)).catch(function (err) {
      clear(view);
      view.appendChild(el("p", { class: "error" }, "Could not load: " + err.message));
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
          api("GET", "/jobs").then(function (jobs) {
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
    return table(["Name", "Target", "Profile", "Schedule", "Last scan (UTC)", "Engagement", "Checks", ""], rows, "No target in service.toml.");
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
