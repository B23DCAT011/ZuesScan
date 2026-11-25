"""Alert routes (G23): besides the main webhook, [[notify.routes]] send some alerts
elsewhere - P1 findings to the on-call channel, a customer's targets to its channel. Each
destination is a row of its own in the outbox, delivered and retried on its own."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_alerts import SECRET, Clock, a_run

from zues_scan.alerts import Alert, RunFacts
from zues_scan.server import notify
from zues_scan.server.config import (
    ConfigError,
    Notify,
    Route,
    ServiceConfig,
    from_environment,
    load_config,
)
from zues_scan.storage import Storage

MAIN = "https://hooks.example.com/main/secret"
ONCALL = Route("oncall", "https://oncall.example.com/x", min_priority="P1")
ACME = Route("acme", "https://acme.example.com/x", targets=("acme-*",), min_priority="P3")
SETTINGS = Route("audit", "https://audit.example.com/x", kinds=("config_changed",))


def run_alert(target: str = "acme-web") -> Any:
    items: list[dict[str, Any]] = [
        {"kind": "fake_fix", "finding_id": 1, "title": "Old flaw", "host": "10.0.0.5"},
        {"kind": "new", "priority": "P1", "title": "KEV", "cve": "CVE-1", "host": "h", "why": "w"},
        {"kind": "new", "priority": "P3", "title": "Meh", "cve": "CVE-3", "host": "h", "why": "w"},
    ]
    return Alert("run", notify.message(target, 7, items))


def kinds_of(alert: Any) -> list[str]:
    return [f"{i['kind']}:{i.get('priority', '')}" for i in alert.payload["items"]]


def test_each_destination_keeps_what_it_takes() -> None:
    settings = Notify(webhook=MAIN, min_priority="P2", routes=(ONCALL, ACME, SETTINGS))
    routed = {a.destination: a for a in notify.route(settings, run_alert())}
    assert set(routed) == {None, "oncall", "acme"}  # not the settings channel
    assert kinds_of(routed[None]) == ["fake_fix:", "new:P1"]  # [notify]'s P2
    assert kinds_of(routed["oncall"]) == ["fake_fix:", "new:P1"]
    assert kinds_of(routed["acme"]) == ["fake_fix:", "new:P1", "new:P3"]  # its P3
    assert "Meh" not in routed[None].payload["text"] and "Meh" in routed["acme"].payload["text"]

    other = {a.destination for a in notify.route(settings, run_alert("globex-web"))}
    assert other == {None, "oncall"}  # another customer's target: not acme's channel


def test_alerts_about_no_target_go_where_no_target_is_asked() -> None:
    settings = Notify(webhook=None, routes=(ONCALL, ACME, SETTINGS))
    locked = notify.locked_out("203.0.113.9", 10, 900)
    assert [a.destination for a in notify.route(settings, locked)] == ["oncall"]
    test = notify.delivery_test("root")
    assert [a.destination for a in notify.route(settings, test)] == ["oncall"]
    nothing_left = replace(run_alert(), payload=notify.message("x", 1, []))
    assert notify.route(Notify(webhook=MAIN), nothing_left) == []


def test_a_run_alert_holds_what_the_loosest_destination_wants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[str] = []

    def found(run: Any, changes: Any, min_priority: str) -> list[dict[str, Any]]:
        asked.append(min_priority)
        return list(run_alert().payload["items"])

    monkeypatch.setattr(notify, "alerts", found)
    policy = notify.RunAlerts(Notify(webhook=MAIN, min_priority="P1", routes=(ACME,)), "acme-web")
    routed = {a.destination: a for a in policy(RunFacts(a_run(), 7, [], 0))}
    assert asked == ["P3"]  # the route's P3 is looser than [notify]'s P1
    assert kinds_of(routed[None]) == ["fake_fix:", "new:P1"]
    assert kinds_of(routed["acme"]) == ["fake_fix:", "new:P1", "new:P3"]
    assert [i["kind"] for i in policy.items] == ["fake_fix", "new"]  # the job's summary: P1


def test_each_row_goes_to_its_own_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    Clock(monkeypatch)
    service = ServiceConfig(
        path="x",
        db=str(tmp_path / "zues.db"),
        notify=Notify(webhook=MAIN, secret=SECRET, routes=(ONCALL, ACME)),
    )
    ids = notify.queue_all(service, run_alert())
    assert len(ids) == 3
    got: list[tuple[str, dict[str, Any]]] = []
    report = notify.flush(
        service, post=lambda url, body, headers: got.append((url, json.loads(body)))
    )
    assert report.sent == 3
    assert sorted(url for url, _ in got) == sorted([MAIN, ONCALL.webhook, ACME.webhook])

    # A route taken out of the configuration: its waiting alerts are given up, said why.
    later = notify.queue_all(service, notify.delivery_test("root"))
    gone = replace(service, notify=replace(service.notify, routes=(ACME,)))
    report = notify.flush(gone, post=lambda *a: None)
    assert (report.sent, report.gave_up) == (1, 1)  # main sent; acme takes no test alert
    with Storage(tmp_path / "zues.db") as store:
        rows = {r["destination"]: r for r in store.alert_rows(ids=later)}
    assert rows["oncall"]["last_error"] == "no route named 'oncall' any more"


def test_a_lasting_condition_is_held_back_per_destination(tmp_path: Path) -> None:
    service = ServiceConfig(
        path="x", db=str(tmp_path / "zues.db"), notify=Notify(webhook=MAIN, routes=(ONCALL,))
    )
    first = notify.queue_all(service, notify.job_failed("lab", "boom"))
    again = notify.queue_all(service, notify.job_failed("lab", "boom"))
    assert len(first) == 2 and again == []


# --- configuration ------------------------------------------------------------------------------

TOML = """
[service]
db = "zues.db"

[notify]
webhook = "https://hooks.example.com/main"
min_priority = "P2"

[[notify.routes]]
name = "oncall"
webhook = "https://oncall.example.com/x"
min_priority = "P1"

[[notify.routes]]
name = "acme"
webhook = "https://acme.example.com/x"
targets = ["acme-*"]
kinds = ["run", "scan_failed"]
"""


def test_routes_in_service_toml(tmp_path: Path) -> None:
    path = tmp_path / "service.toml"
    path.write_text(TOML, encoding="utf-8")
    routes = load_config(path).notify.routes
    assert routes == (
        Route("oncall", "https://oncall.example.com/x", "P1"),
        Route("acme", "https://acme.example.com/x", None, ("acme-*",), ("run", "scan_failed")),
    )


@pytest.mark.parametrize(
    ("table", "error"),
    [
        ('name = "Bad Name"\nwebhook = "https://x"', "name must be"),
        ('name = "a"\nwebhook = "ftp://x"', "webhook must be an http"),
        ('name = "a"\nwebhook = "https://x"\nmin_priority = "P9"', "min_priority must be"),
        ('name = "a"\nwebhook = "https://x"\nkinds = ["pager"]', "kinds must be a list of"),
        ('name = "a"\nwebhook = "https://x"\nchannel = "#x"', "unknown key"),
    ],
)
def test_a_wrong_route_stops_the_service(tmp_path: Path, table: str, error: str) -> None:
    path = tmp_path / "service.toml"
    path.write_text(f'[service]\ndb = "zues.db"\n\n[[notify.routes]]\n{table}\n', encoding="utf-8")
    with pytest.raises(ConfigError, match=error):
        load_config(path)


def test_two_routes_of_one_name_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "service.toml"
    path.write_text(TOML.replace('name = "acme"', 'name = "oncall"'), encoding="utf-8")
    with pytest.raises(ConfigError, match="two routes have the same name"):
        load_config(path)


def test_routes_from_the_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "zues.db"))
    monkeypatch.setenv(
        "ZUES_NOTIFY_ROUTES",
        json.dumps([{"name": "oncall", "webhook": ONCALL.webhook, "min_priority": "P1"}]),
    )
    assert from_environment().notify.routes == (ONCALL,)
    monkeypatch.setenv("ZUES_NOTIFY_ROUTES", "{not json")
    with pytest.raises(ConfigError, match="ZUES_NOTIFY_ROUTES must be a JSON list"):
        from_environment()


def test_routes_only_send(tmp_path: Path) -> None:
    assert Notify(routes=(ONCALL,)).sends() and not Notify().sends()
    facts = RunFacts(run=a_run(), run_id=1, changes=[], failed_before=0)
    assert notify.RunAlerts(Notify(), "lab")(facts) == []
