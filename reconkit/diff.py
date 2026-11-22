"""What changed between two runs (D1): hosts, ports, versions, findings.

A diff is only as good as the runs are comparable. Two runs that scanned different
targets, ports (profiles) or used different CVE data look different without anything
having changed; `RunDiff.caveats` says so instead of hiding it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reconkit.inventory import cve_data_kind, host_key
from reconkit.orchestrator import RunStatus, ScanRun
from reconkit.schema import Asset, Finding, Service


@dataclass(frozen=True, slots=True)
class ServiceChange:
    host: str
    port: int
    protocol: str
    before: str  # "OpenSSH 7.4"
    after: str


@dataclass
class RunDiff:
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)
    services_added: list[tuple[str, Service]] = field(default_factory=list)
    services_removed: list[tuple[str, Service]] = field(default_factory=list)
    services_changed: list[ServiceChange] = field(default_factory=list)
    findings_added: list[tuple[str, Finding]] = field(default_factory=list)
    findings_removed: list[tuple[str, Finding]] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any(
            (
                self.hosts_added,
                self.hosts_removed,
                self.services_added,
                self.services_removed,
                self.services_changed,
                self.findings_added,
                self.findings_removed,
            )
        )


def diff_runs(before: ScanRun, after: ScanRun) -> RunDiff:
    """What `after` shows differently from `before`."""
    result = RunDiff(caveats=_caveats(before, after))
    old = {_key(a): a for a in before.assets}
    new = {_key(a): a for a in after.assets}
    result.hosts_added = [_label(new[k]) for k in new if k not in old]
    result.hosts_removed = [_label(old[k]) for k in old if k not in new]
    for key in new.keys() & old.keys():
        _services(result, _label(new[key]), old[key], new[key])
    old_findings = {f.fingerprint: (_label(a), f) for a in before.assets for f in a.findings}
    new_findings = {f.fingerprint: (_label(a), f) for a in after.assets for f in a.findings}
    result.findings_added = [new_findings[fp] for fp in new_findings if fp not in old_findings]
    result.findings_removed = [old_findings[fp] for fp in old_findings if fp not in new_findings]
    return result


def _services(result: RunDiff, label: str, old: Asset, new: Asset) -> None:
    before = {(s.port, s.protocol): s for s in old.services}
    after = {(s.port, s.protocol): s for s in new.services}
    for key, service in after.items():
        if key not in before:
            result.services_added.append((label, service))
        elif _software(before[key]) != _software(service):
            result.services_changed.append(
                ServiceChange(label, key[0], key[1], _software(before[key]), _software(service))
            )
    result.services_removed += [(label, s) for k, s in before.items() if k not in after]


def _caveats(before: ScanRun, after: ScanRun) -> list[str]:
    caveats = []
    if RunStatus.FAILED in (before.status, after.status):
        caveats.append("a failed run has no results: everything looks added or removed")
    if before.target != after.target:
        caveats.append(f"different targets ({before.target} vs {after.target})")
    if before.profile_settings != after.profile_settings:
        caveats.append(
            f"different scan profiles ({before.profile or '?'} vs {after.profile or '?'}): "
            "ports scanned by only one of them show up as opened or closed"
        )
    if cve_data_kind(_source(before)) != cve_data_kind(_source(after)):
        caveats.append("different CVE data: findings differ for that reason too")
    fp_schemes = {
        f.fingerprint.split(":")[0] for r in (before, after) for a in r.assets for f in a.findings
    }
    if len(fp_schemes) > 1:
        caveats.append("findings fingerprinted with different schemes cannot be matched")
    return caveats


def _source(run: ScanRun) -> str | None:
    return run.cve_source


def _key(asset: Asset) -> str:
    return host_key(asset.ip, asset.host)


def _label(asset: Asset) -> str:
    return asset.host if asset.ip in (None, asset.host) else f"{asset.host} ({asset.ip})"


def _software(service: Service) -> str:
    return " ".join(p for p in (service.name, service.product, service.version) if p) or "?"
