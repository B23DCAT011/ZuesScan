"""httpx sends a virtual host's name as the TLS SNI too (G29): one run per name on TLS
services, since `-sni` is one name per run and httpx sends no SNI for an address."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from zues_scan.plugins import httpx as httpx_plugin
from zues_scan.plugins.httpx import HttpxPlugin, plan_inputs, sni_runs
from zues_scan.schema import Asset, ScanTarget, Service

PLAN = ScanTarget("10.0.0.0/24", ("10.0.0.0/24",))


def assets() -> list[Asset]:
    return [
        Asset(
            "shop.acme.test",
            "10.0.0.5",
            [Service(80, name="http"), Service(443, name="https"), Service(8080, name="ssl/http")],
            names=["shop.acme.test", "api.acme.test"],
        )
    ]


def test_names_on_tls_services_get_their_own_run() -> None:
    inputs, _ = plan_inputs(assets())
    runs, over = sni_runs(inputs, assets())
    assert over == 0
    shared, *named = runs
    assert shared == (
        None,
        [
            "10.0.0.5:80",
            "10.0.0.5:443",
            "10.0.0.5:8080",
            "shop.acme.test,10.0.0.5:80",
            "api.acme.test,10.0.0.5:80",
        ],
    )
    assert named == [
        ("shop.acme.test", ["shop.acme.test,10.0.0.5:443", "shop.acme.test,10.0.0.5:8080"]),
        ("api.acme.test", ["api.acme.test,10.0.0.5:443", "api.acme.test,10.0.0.5:8080"]),
    ]


def test_over_the_cap_names_share_the_run_without_sni(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx_plugin, "MAX_SNI_RUNS", 1)
    inputs, _ = plan_inputs(assets())
    runs, over = sni_runs(inputs, assets())
    assert over == 1 and [sni for sni, _ in runs] == [None, "shop.acme.test"]
    assert "api.acme.test,10.0.0.5:443" in runs[0][1]


def test_each_run_sends_its_name_as_sni(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str | None, list[str]]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        lines = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        sni = command[command.index("-sni") + 1] if "-sni" in command else None
        calls.append((sni, lines))
        out = [
            json.dumps(
                {
                    "input": line,
                    "url": f"https://{line.rpartition(',')[2]}",
                    "status_code": 200,
                    "title": f"site {sni or 'default'}",
                }
            )
            for line in lines
        ]
        return subprocess.CompletedProcess(command, 0, "\n".join(out) + "\n", "")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", run)
    result = HttpxPlugin().check(PLAN, assets())

    assert [sni for sni, _ in calls] == [None, "shop.acme.test", "api.acme.test"]
    assert len(result.raw) == 3 and result.raw[1].command[-2:] == ("-sni", "shop.acme.test")
    (asset,) = result.assets
    tls = next(s for s in asset.services if s.port == 443)
    assert {p.host: p.title for p in tls.vhosts} == {
        "shop.acme.test": "site shop.acme.test",
        "api.acme.test": "site api.acme.test",
    }
    assert "6 of 6 site(s) by name answered" in result.notes
