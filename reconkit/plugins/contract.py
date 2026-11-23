"""The rules every plugin must keep, as checks a plugin's own tests can run.

    from reconkit.plugins import contract

    def test_my_check_keeps_the_contract():
        contract.assert_ok(contract.check_check(MyCheck(), plan, assets))

Each function returns the list of rules broken (empty: all kept), so a test can show
them all at once. They encode what the built-in plugins already do: stay inside the
addresses the scope guard approved, keep the tool's raw output as evidence, report
failures as `ScanError`, and say how far they go with a target (`activity`).
"""

from __future__ import annotations

from typing import Any

from reconkit.plugins.base import DiscoveryResult, ScanError, ScanResult
from reconkit.plugins.registry import KINDS, PluginError, PluginSpec
from reconkit.schema import Asset, Finding, ScanTarget
from reconkit.scope import Activity


def check_spec(spec: Any) -> list[str]:
    if not isinstance(spec, PluginSpec):
        return ["the entry point must give a reconkit.plugins.registry.PluginSpec"]
    problems = []
    if spec.kind not in KINDS:
        problems.append(f"kind {spec.kind!r} is not one of {', '.join(KINDS)}")
    if not callable(spec.factory):
        problems.append("factory is not callable")
    return problems


def _common(plugin: Any) -> list[str]:
    problems = []
    if not isinstance(getattr(plugin, "name", None), str) or not plugin.name:
        problems.append("it has no name")
    if not isinstance(getattr(plugin, "activity", None), Activity):
        problems.append(
            "it does not say how far it goes (class attribute activity = Activity.PASSIVE, "
            "Activity.SCAN or Activity.ACTIVE)"
        )
    try:
        version = plugin.version()
        if version is not None and not isinstance(version, str):
            problems.append("version() must return a string or None")
    except Exception as exc:  # noqa: BLE001 - the rule is precisely "must not raise"
        problems.append(f"version() raised {type(exc).__name__}: it must never raise")
    if not isinstance(plugin.is_available(), bool):
        problems.append("is_available() must return a bool")
    return problems


def _raw(result: ScanResult | DiscoveryResult) -> list[str]:
    if not result.raw:
        return ["it kept no raw output: the tool's own output is the evidence of a run"]
    return [
        f"raw output {i} has no text content"
        for i, raw in enumerate(result.raw)
        if not isinstance(raw.content, str)
    ]


def _findings(asset: Asset) -> list[str]:
    problems = []
    for f in asset.findings:
        if not isinstance(f, Finding) or not f.title:
            problems.append(f"a finding on {asset.ip} has no title")
    return problems


def check_scanner(plugin: Any, target: ScanTarget) -> list[str]:
    """Scan `target` (with fakes for the tool) and check what came back."""
    problems = _common(plugin)
    try:
        result = plugin.scan(target)
    except ScanError:
        return problems  # a failure reported the right way is allowed
    except Exception as exc:  # noqa: BLE001
        return [*problems, f"scan() raised {type(exc).__name__}: failures must be ScanError"]
    if not isinstance(result, ScanResult):
        return [*problems, "scan() must return a ScanResult"]
    allowed = set(target.addresses)
    for asset in result.assets:
        if asset.ip not in allowed or asset.ip in target.exclude:
            problems.append(f"it reported {asset.ip}, which it was not asked to scan")
        problems += _findings(asset)
    return problems + _raw(result)


def check_check(plugin: Any, plan: ScanTarget, assets: list[Asset]) -> list[str]:
    """Run the check on `assets` (with fakes for the tool) and check what came back."""
    problems = _common(plugin)
    try:
        result = plugin.check(plan, assets)
    except ScanError:
        return problems
    except Exception as exc:  # noqa: BLE001
        return [*problems, f"check() raised {type(exc).__name__}: failures must be ScanError"]
    if not isinstance(result, ScanResult):
        return [*problems, "check() must return a ScanResult"]
    known = {a.ip for a in assets}
    for asset in result.assets:
        if asset.ip not in known:
            problems.append(
                f"it reported {asset.ip}: a check may only report on hosts it was given"
            )
        problems += _findings(asset)
    if result.assets:
        problems += _raw(result)
    return problems


def check_discovery(plugin: Any, domain: str) -> list[str]:
    problems = _common(plugin)
    try:
        result = plugin.discover(domain)
    except ScanError:
        return problems
    except Exception as exc:  # noqa: BLE001
        return [*problems, f"discover() raised {type(exc).__name__}: failures must be ScanError"]
    if not isinstance(result, DiscoveryResult):
        return [*problems, "discover() must return a DiscoveryResult"]
    outside = [n for n in result.names if not n.endswith("." + domain)]
    if outside:
        problems.append(f"it returned names outside {domain}: {', '.join(outside[:5])}")
    return problems + _raw(result)


def assert_ok(problems: list[str]) -> None:
    if problems:
        raise AssertionError("plugin contract broken:\n- " + "\n- ".join(problems))


__all__ = [
    "PluginError",
    "assert_ok",
    "check_check",
    "check_discovery",
    "check_scanner",
    "check_spec",
]
