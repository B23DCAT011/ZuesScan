"""CVE stage — turn a fingerprinted Service into Findings.

A `CveSource` takes a service and returns the known vulnerabilities for it, as
:class:`~reconkit.schema.Finding` objects. Mirroring the scanner-plugin design, the
source is an interface; :class:`LocalCveSource` reads a JSON data file (the bundled
seed by default). How a service is matched — CPE, version ranges, confidence — is in
:mod:`reconkit.cve.match`, shared by every source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from reconkit.cve.match import affected_range, identify, to_finding
from reconkit.cve.records import CveDataError, CveRecord, load_records
from reconkit.schema import Finding, Service

# Bundled seed data ships with the package.
DEFAULT_SEED = Path(__file__).resolve().parent.parent / "data" / "cve_seed.json"

__all__ = ["DEFAULT_SEED", "CveDataError", "CveRecord", "CveSource", "LocalCveSource"]


class CveSource(Protocol):
    """A source of known vulnerabilities for a given service."""

    name: str

    def find(self, service: Service, asset_host: str) -> list[Finding]:
        """Return findings for `service` (empty list if none known)."""
        ...


class LocalCveSource:
    """CVE source backed by a JSON data file, indexed by product in memory."""

    name = "local-seed"

    def __init__(self, path: str | Path = DEFAULT_SEED) -> None:
        self.path = Path(path)
        if self.path.resolve() != DEFAULT_SEED:
            self.name = f"local file {self.path.name}"
        self._by_product: dict[str, list[CveRecord]] = {}
        for record in load_records(path):
            for product in {a.cpe.product for a in record.affects}:
                self._by_product.setdefault(product, []).append(record)

    def find(self, service: Service, asset_host: str) -> list[Finding]:
        software = identify(service)
        if software is None:
            return []  # cannot match without knowing the product and its version
        findings = []
        for record in self._by_product.get(software.product, []):
            matched = affected_range(software, record)
            if matched is not None:
                # No fingerprint here: it depends on the host's address, which only the
                # orchestrator knows. It fingerprints every finding of a run in one place.
                findings.append(
                    to_finding(service, asset_host, software, record, matched, self.name)
                )
        return findings
