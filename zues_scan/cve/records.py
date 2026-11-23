"""What ZuesScan knows about a vulnerability, and the file format it is kept in.

A :class:`CveRecord` says which products a CVE affects as a list of
:class:`AffectedRange` — the same shape as NVD's `cpeMatch` entries: a CPE naming the
product (and maybe one exact version), plus optional bounds:

    {"cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
     "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"}

The bundled seed (`zues_scan/data/cve_seed.json`) and the NVD cache use it alike.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zues_scan.cve.cpe import Cpe, CpeError, parse_cpe
from zues_scan.cve.version import Version
from zues_scan.schema import Severity

FORMAT = "zues-cve"
LEGACY_FORMATS = ("reconkit-cve",)  # files written before the rename stay readable
FORMAT_VERSION = 2

_BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


class CveDataError(Exception):
    """A CVE data file cannot be used."""


@dataclass(frozen=True, slots=True)
class AffectedRange:
    """The versions of one product that a CVE affects."""

    cpe: Cpe
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    def contains(self, version: Version) -> bool:
        """Is `version` (an upstream release) one of the affected versions?"""
        if self.cpe.version is not None:
            return version == Version(self.cpe.version)
        if self.start_including and version < Version(self.start_including):
            return False
        if self.start_excluding and version <= Version(self.start_excluding):
            return False
        if self.end_including and version > Version(self.end_including):
            return False
        if self.end_excluding and version >= Version(self.end_excluding):
            return False
        # A range with no version and no bound would mean "every version ever":
        # NVD uses that for products it has not analysed; it proves nothing.
        return self.is_bounded()

    def is_bounded(self) -> bool:
        return self.cpe.version is not None or any(
            (self.start_including, self.start_excluding, self.end_including, self.end_excluding)
        )

    def describe(self) -> str:
        """e.g. "f5:nginx >= 0.6.18, < 1.20.1"."""
        name = f"{self.cpe.vendor}:{self.cpe.product}"
        if self.cpe.version is not None:
            return f"{name} {self.cpe.version}"
        bounds = [
            f">= {self.start_including}" if self.start_including else "",
            f"> {self.start_excluding}" if self.start_excluding else "",
            f"<= {self.end_including}" if self.end_including else "",
            f"< {self.end_excluding}" if self.end_excluding else "",
        ]
        return f"{name} {', '.join(b for b in bounds if b)}"

    def to_json(self) -> dict[str, str]:
        data = {"cpe": str(self.cpe)}
        for key, value in zip(
            _BOUNDS,
            (self.start_including, self.start_excluding, self.end_including, self.end_excluding),
            strict=True,
        ):
            if value is not None:
                data[key] = value
        return data


@dataclass(frozen=True, slots=True)
class CveRecord:
    """One vulnerability and the products it affects."""

    id: str  # "CVE-2021-23017"
    severity: Severity
    affects: tuple[AffectedRange, ...]
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: tuple[str, ...] = ()
    kev_added: str | None = None  # date it entered CISA's KEV catalog
    epss: float | None = None  # FIRST EPSS score; changes daily, so never in a data file

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "cve": self.id,
            "title": self.title,
            "severity": str(self.severity),
            "description": self.description,
        }
        if self.cvss_score is not None:
            data["cvss"] = {"score": self.cvss_score, "vector": self.cvss_vector}
        if self.cwe:
            data["cwe"] = list(self.cwe)
        if self.kev_added:
            data["kev"] = {"added": self.kev_added}
        data["affects"] = [a.to_json() for a in self.affects]
        return data


def range_from_json(data: dict[str, Any]) -> AffectedRange:
    unknown = set(data) - {"cpe", *_BOUNDS}
    if unknown:
        raise CveDataError(f"unknown key(s) in an affected range: {', '.join(sorted(unknown))}")
    try:
        cpe = parse_cpe(str(data["cpe"]))
    except KeyError:
        raise CveDataError("an affected range needs a 'cpe'") from None
    except CpeError as exc:
        raise CveDataError(str(exc)) from None
    bounds = {key: data.get(key) for key in _BOUNDS}
    for key, value in bounds.items():
        if value is not None:
            try:
                Version(str(value))
            except ValueError:
                raise CveDataError(f"{key} is not a version: {value!r}") from None
    return AffectedRange(
        cpe=cpe,
        start_including=bounds["versionStartIncluding"],
        start_excluding=bounds["versionStartExcluding"],
        end_including=bounds["versionEndIncluding"],
        end_excluding=bounds["versionEndExcluding"],
    )


def record_from_json(data: dict[str, Any]) -> CveRecord:
    try:
        cve = str(data["cve"])
        severity = Severity(data.get("severity", "info"))
        affects = tuple(range_from_json(a) for a in data["affects"])
        cvss = data.get("cvss") or {}
        score = cvss.get("score")
        if score is not None and not (
            isinstance(score, int | float) and not isinstance(score, bool) and 0 <= score <= 10
        ):
            raise ValueError(f"CVSS score must be 0-10, not {score!r}")
        kev = data.get("kev") or {}
    except KeyError as exc:
        raise CveDataError(f"entry {data.get('cve', '?')}: missing {exc}") from None
    except (ValueError, AttributeError) as exc:
        raise CveDataError(f"entry {data.get('cve', '?')}: {exc}") from None
    return CveRecord(
        id=cve,
        severity=severity,
        affects=affects,
        title=str(data.get("title", "")),
        description=str(data.get("description", "")),
        cvss_score=None if score is None else float(score),
        cvss_vector=cvss.get("vector"),
        cwe=tuple(str(c) for c in data.get("cwe", [])),
        kev_added=kev.get("added"),
    )


def load_records(path: str | Path) -> list[CveRecord]:
    """Read a CVE data file (format `zues-cve`, version 2)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CveDataError(f"CVE data file not found: {path}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CveDataError(f"cannot read CVE data file {path}: {exc}") from None
    if not isinstance(data, dict):
        raise CveDataError(f"{path}: not a ZuesScan CVE data file")
    if data.get("format") not in (FORMAT, *LEGACY_FORMATS) or data.get("version") != FORMAT_VERSION:
        old = isinstance(data.get("entries"), list) and "format" not in data
        hint = (
            " It looks like the old format (product + exact version, before CPE ranges):"
            " give each entry an 'affects' list of CPE ranges, see zues_scan/data/cve_seed.json."
            if old
            else ""
        )
        raise CveDataError(
            f'{path}: expected "format": "{FORMAT}", "version": {FORMAT_VERSION}.{hint}'
        )
    try:
        return [record_from_json(entry) for entry in data["entries"]]
    except CveDataError as exc:
        raise CveDataError(f"{path}: {exc}") from None
