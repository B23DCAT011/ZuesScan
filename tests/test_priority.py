"""Tests for exploitation signals (KEV, EPSS) and finding priority (G11)."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime
from pathlib import Path

import pytest

from zues_scan.cve import LocalCveSource
from zues_scan.cve.cache import CveCache, refresh_epss, refresh_kev, sync
from zues_scan.cve.feeds import EPSS_URL, KEV_URL, FeedError, parse_epss, parse_kev
from zues_scan.cve.nvd import NvdClient
from zues_scan.priority import Priority, priority, reason, sort_key
from zues_scan.schema import Finding, Service, Severity

DATA = Path(__file__).parent / "data"
KEV = (DATA / "kev_sample.json").read_bytes()
EPSS = gzip.compress(
    b"#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z\n"
    b"cve,epss,percentile\n"
    b"CVE-2021-23017,0.12345,0.95\n"
    b"CVE-2018-15473,0.98675,0.99925\n"
    b"CVE-2021-41773,0.99992,0.99986\n"
    b"bogus,1,1\n"
    b"CVE-2020-0001,7,0.5\n"
)
NOW = datetime(2026, 11, 22, tzinfo=UTC)


def _finding(**facts: object) -> Finding:
    return Finding(asset="h", title="t", **facts)  # type: ignore[arg-type]


# --- priority ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("facts", "expected", "why"),
    [
        ({"kev_added": "2021-11-03", "cvss_score": 3.0}, Priority.P1, "CISA KEV since 2021-11-03"),
        ({"epss": 0.5, "cvss_score": 4.0}, Priority.P2, "EPSS 50%"),
        ({"cvss_score": 9.8}, Priority.P2, "CVSS 9.8"),
        ({"cvss_score": 5.0, "epss": 0.02}, Priority.P3, "EPSS 2.0%"),
        ({"cvss_score": 7.5}, Priority.P3, "CVSS 7.5"),
        ({"cvss_score": 6.5, "epss": 0.001}, Priority.P4, "CVSS 6.5, EPSS 0.1%"),
        ({"severity": Severity.CRITICAL}, Priority.P2, "severity 9.0"),  # no CVSS: stand-in
        ({"severity": Severity.LOW}, Priority.P4, "severity 0.1"),
    ],
)
def test_priority_rules(facts: dict[str, object], expected: Priority, why: str) -> None:
    finding = _finding(**facts)
    assert priority(finding) == expected
    assert why in reason(finding)


def test_exploited_medium_ranks_above_unexploited_critical() -> None:
    exploited = _finding(severity=Severity.MEDIUM, cvss_score=5.3, kev_added="2024-01-01")
    critical = _finding(severity=Severity.CRITICAL, cvss_score=9.8, epss=0.0004)
    likely = _finding(severity=Severity.MEDIUM, cvss_score=5.3, epss=0.9)
    assert sorted([critical, likely, exploited], key=sort_key) == [exploited, likely, critical]


# --- feeds ------------------------------------------------------------------------------------


def test_kev_catalog_is_read_and_bad_rows_skipped() -> None:
    version, entries = parse_kev(KEV)
    assert version == "2026.11.20"
    assert [(e.cve, e.added, e.ransomware) for e in entries] == [
        ("CVE-2021-41773", "2021-11-03", True),
        ("CVE-2021-23017", "2026-01-15", False),
    ]


@pytest.mark.parametrize(
    "data", [b"not json", b'{"vulnerabilities": [{"x": 1}]}', b'{"vulnerabilities": []}']
)
def test_unusable_kev_catalog_is_refused(data: bytes) -> None:
    with pytest.raises(FeedError):
        parse_kev(data)


def test_epss_scores_are_read_and_bad_rows_skipped() -> None:
    date, scores = parse_epss(EPSS)
    assert date == "2026-11-21T12:00:24Z"
    assert [(s.cve, s.score) for s in scores] == [
        ("CVE-2021-23017", 0.12345),
        ("CVE-2018-15473", 0.98675),
        ("CVE-2021-41773", 0.99992),
    ]


@pytest.mark.parametrize("data", [b"plain text", gzip.compress(b"cve,epss,percentile\n")])
def test_unusable_epss_file_is_refused(data: bytes) -> None:
    with pytest.raises(FeedError):
        parse_epss(data)


# --- cache + matching ---------------------------------------------------------------------------


def _feeds(url: str) -> bytes:
    return {KEV_URL: KEV, EPSS_URL: EPSS}[url]


def test_findings_from_the_cache_carry_kev_and_epss(tmp_path: Path) -> None:
    import json

    page = json.loads((DATA / "nvd_page.json").read_text(encoding="utf-8"))

    def fetch(url: str, headers: dict[str, str]) -> object:
        return page

    with CveCache(tmp_path / "cve.db", create=True) as cache:
        sync(cache, NvdClient(fetch=fetch, sleep=lambda _s: None))
        assert refresh_kev(cache, _feeds, now=lambda: NOW) == ("2026.11.20", 2)
        assert refresh_epss(cache, _feeds, now=lambda: NOW) == ("2026-11-21T12:00:24Z", 3)
        assert cache.feeds()["kev"] == ("2026-11-22T00:00:00+00:00", "2026.11.20", 2)

        from zues_scan.cve.cache import NvdCveSource

        source = NvdCveSource(cache)
        (nginx,) = source.find(Service(port=80, product="nginx", version="1.18.0"), "h")
        assert (nginx.kev_added, nginx.epss, nginx.cvss_score) == ("2026-01-15", 0.12345, 7.7)
        assert nginx.cwe == ("CWE-193",)
        assert priority(nginx) == Priority.P1
        details = cache.details("CVE-2021-23017")
        assert details is not None and "in CISA KEV since 2026-01-15" in details["kev"]
        assert details["epss"] == "12.35% (percentile 95.0%)"

        # A new catalog replaces the old one.
        refresh_kev(cache, lambda url: KEV.replace(b'"CVE-2021-23017"', b'"CVE-2000-0001"'))
        (nginx,) = source.find(Service(port=80, product="nginx", version="1.18.0"), "h")
        assert nginx.kev_added is None


def test_seed_carries_cvss_cwe_and_kev() -> None:
    svc = Service(port=80, product="Apache httpd", version="2.4.49")
    (finding,) = LocalCveSource().find(svc, "h")
    assert (finding.cvss_score, finding.cwe, finding.kev_added) == (9.8, ("CWE-22",), "2021-11-03")
    assert finding.epss is None  # changes daily: only in an NVD cache
    assert priority(finding) == Priority.P1
