"""Tests for the NVD client, the local cache and the cache-backed CVE source (G9).

No network: the client's transport is replaced by canned pages (tests/data/
nvd_page.json is trimmed from real NVD API 2.0 answers).
"""

from __future__ import annotations

import copy
import io
import json
import urllib.error
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from reconkit.cve.cache import CacheError, CveCache, NvdCveSource, sync
from reconkit.cve.nvd import NvdClient, NvdError, _Retryable, http_fetch, parse_cve, title_from
from reconkit.schema import Confidence, Service, Severity

PAGE = json.loads((Path(__file__).parent / "data" / "nvd_page.json").read_text(encoding="utf-8"))
NGINX, OPENSSH, REJECTED = (v["cve"] for v in PAGE["vulnerabilities"])


class FakeNvd:
    """Answers like NVD from a list of CVEs, and records every request."""

    def __init__(self, cves: list[dict[str, Any]], failures: list[Exception] | None = None):
        self.cves = cves
        self.failures = list(failures or [])
        self.requests: list[tuple[dict[str, str], dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> Any:
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        self.requests.append((params, headers))
        if self.failures:
            raise self.failures.pop(0)
        start, size = int(params["startIndex"]), int(params["resultsPerPage"])
        chunk = self.cves[start : start + size]
        return {"totalResults": len(self.cves), "vulnerabilities": [{"cve": c} for c in chunk]}


def _client(fake: FakeNvd, **kwargs: Any) -> tuple[NvdClient, list[float]]:
    slept: list[float] = []
    return NvdClient(fetch=fake, sleep=slept.append, **kwargs), slept


# --- reading NVD records -------------------------------------------------------------------


def test_parse_takes_cvss_cwe_and_the_product_ranges() -> None:
    entry = parse_cve(NGINX)
    assert entry is not None
    assert entry.record.id == "CVE-2021-23017"
    assert entry.record.severity == Severity.HIGH
    assert (entry.cvss_version, entry.cvss_score) == ("3.1", 7.7)
    assert entry.cvss_vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L"
    assert entry.cwe == ("CWE-193",)
    assert [a.describe() for a in entry.record.affects] == ["f5:nginx >= 0.6.18, < 1.20.1"]
    title = entry.record.title
    assert title.startswith("A security issue in nginx resolver was identified, which might")
    assert title.endswith(" who is…") and len(title) <= 90


def test_platform_entries_are_kept_as_their_own_ranges() -> None:
    entry = parse_cve(OPENSSH)
    assert entry is not None
    assert {a.describe() for a in entry.record.affects} == {
        "openbsd:openssh <= 7.7",
        "debian:debian_linux 9.0",
    }


def test_rejected_cve_is_not_kept() -> None:
    assert parse_cve(REJECTED) is None


def test_severity_falls_back_to_older_cvss_then_info() -> None:
    cve = copy.deepcopy(NGINX)
    del cve["metrics"]["cvssMetricV31"]
    cve["metrics"]["cvssMetricV2"] = [
        {
            "type": "Primary",
            "baseSeverity": "MEDIUM",
            "cvssData": {"version": "2.0", "baseScore": 4.3},
        }
    ]
    entry = parse_cve(cve)
    assert entry is not None and (entry.record.severity, entry.cvss_score) == (Severity.MEDIUM, 4.3)
    cve["metrics"] = {"ssvcV203": [{"other": {}}]}  # no CVSS at all
    entry = parse_cve(cve)
    assert entry is not None and (entry.record.severity, entry.cvss_score) == (Severity.INFO, None)


def test_unusable_ranges_are_skipped() -> None:
    cve = copy.deepcopy(NGINX)
    matches = [
        {"vulnerable": False, "criteria": "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},  # unbounded
        {"vulnerable": True, "criteria": "not-a-cpe"},
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "?",
        },
    ]
    cve["configurations"] = [
        {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]},
        {"nodes": [{"operator": "OR", "negate": True, "cpeMatch": [NGINX_MATCH]}]},
    ]
    entry = parse_cve(cve)
    assert entry is not None and entry.record.affects == ()


NGINX_MATCH = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "1.20.1",
}


def test_cwe_placeholders_are_not_cwes() -> None:
    cve = copy.deepcopy(NGINX)
    cve["weaknesses"] = [{"description": [{"value": "NVD-CWE-noinfo"}, {"value": "CWE-79"}]}]
    entry = parse_cve(cve)
    assert entry is not None and entry.cwe == ("CWE-79",)


def test_title_is_the_first_sentence_shortened() -> None:
    assert title_from("Short one. Then more.") == "Short one"
    assert len(title_from("x" * 200)) == 90


# --- the client: paging, rate limit, retries ------------------------------------------------


def test_pages_through_everything_waiting_between_requests() -> None:
    fake = FakeNvd([NGINX, OPENSSH, REJECTED])
    client, slept = _client(fake, page_size=2)
    pages = list(client.pages())
    assert [len(p) for p in pages] == [2, 1]
    assert [r[0]["startIndex"] for r in fake.requests] == ["0", "2"]
    assert slept == [6.0]  # no key: NVD allows 5 requests per 30 s
    assert "apiKey" not in fake.requests[0][1]
    assert fake.requests[0][1]["User-Agent"].startswith("reconkit/")


def test_api_key_is_sent_as_a_header_and_speeds_things_up() -> None:
    fake = FakeNvd([NGINX, OPENSSH])
    client, slept = _client(fake, api_key="secret", page_size=1)
    list(client.pages(product="cpe:2.3:a:f5:nginx"))
    assert fake.requests[0][1]["apiKey"] == "secret"
    assert "secret" not in str(fake.requests[0][0])  # never in the URL
    assert fake.requests[0][0]["virtualMatchString"] == "cpe:2.3:a:f5:nginx"
    assert slept == [1.0]


def test_changes_are_asked_for_in_windows_of_at_most_120_days() -> None:
    fake = FakeNvd([])
    client, _ = _client(fake)
    until = datetime(2026, 11, 22, tzinfo=UTC)
    list(client.pages(modified_since=until - timedelta(days=200), until=until))
    windows = [(r[0]["lastModStartDate"], r[0]["lastModEndDate"]) for r in fake.requests]
    assert windows == [
        ("2026-05-06T00:00:00.000Z", "2026-09-03T00:00:00.000Z"),
        ("2026-09-03T00:00:00.000Z", "2026-11-22T00:00:00.000Z"),
    ]


def test_retries_with_backoff_then_succeeds() -> None:
    fake = FakeNvd([NGINX], failures=[_Retryable("HTTP 403"), _Retryable("HTTP 503")])
    client, slept = _client(fake)
    assert [len(p) for p in client.pages()] == [1]
    assert slept == [12.0, 24.0]


def test_gives_up_after_the_last_retry() -> None:
    fake = FakeNvd([NGINX], failures=[_Retryable("HTTP 503")] * 3)
    client, _ = _client(fake, retries=2)
    with pytest.raises(NvdError, match="503"):
        list(client.pages())


def test_unexpected_answer_is_an_error() -> None:
    client, _ = _client(lambda url, headers: {"message": "?"})  # type: ignore[arg-type]
    with pytest.raises(NvdError, match="unexpected answer"):
        list(client.pages())


def test_empty_page_stops_the_loop() -> None:
    def lying(url: str, headers: dict[str, str]) -> Any:
        return {"totalResults": 5, "vulnerabilities": []}

    client, _ = _client(lying)  # type: ignore[arg-type]
    assert list(client.pages()) == [[]]


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (urllib.error.HTTPError("u", 403, "Forbidden", {}, io.BytesIO()), _Retryable),  # type: ignore[arg-type]
        (urllib.error.HTTPError("u", 503, "Busy", {}, io.BytesIO()), _Retryable),  # type: ignore[arg-type]
        (urllib.error.HTTPError("u", 404, "Not found", {}, io.BytesIO()), NvdError),  # type: ignore[arg-type]
        (urllib.error.URLError("no route"), _Retryable),
    ],
)
def test_http_errors_are_sorted_into_retry_or_fail(
    monkeypatch: pytest.MonkeyPatch, error: Exception, kind: type[Exception]
) -> None:
    def urlopen(*args: object, **kwargs: object) -> object:
        raise error

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    with pytest.raises(kind) as caught:
        http_fetch("https://nvd.example/x", {})
    if kind is NvdError:
        assert not isinstance(caught.value, _Retryable)


# --- the cache ----------------------------------------------------------------------------


def _cache(tmp_path: Path) -> CveCache:
    return CveCache(tmp_path / "cve.db", create=True)


def test_missing_cache_says_how_to_fill_it(tmp_path: Path) -> None:
    with pytest.raises(CacheError, match="reconkit cve sync"):
        CveCache(tmp_path / "nope.db")


def test_cache_from_a_newer_reconkit_is_refused(tmp_path: Path) -> None:
    with _cache(tmp_path) as cache:
        cache._conn.execute("PRAGMA user_version = 99")
    with pytest.raises(CacheError, match="newer"):
        CveCache(tmp_path / "cve.db")


def test_full_sync_then_only_changes(tmp_path: Path) -> None:
    fake = FakeNvd([NGINX, OPENSSH, REJECTED])
    client, _ = _client(fake)
    first = datetime(2026, 11, 1, tzinfo=UTC)
    with _cache(tmp_path) as cache:
        result = sync(cache, client, now=lambda: first)
        assert (result.changed, result.removed, result.since) == (2, 1, None)
        assert "lastModStartDate" not in fake.requests[0][0]
        assert cache.status().cves == 2

        fake.requests.clear()
        later = sync(cache, client, now=lambda: first + timedelta(days=3))
        params = fake.requests[0][0]
        assert params["lastModStartDate"] == "2026-10-31T23:00:00.000Z"  # last sync - 1 h
        assert params["lastModEndDate"] == "2026-11-04T00:00:00.000Z"
        assert later.since is not None
        assert cache.status().scopes == {"all": "2026-11-04T00:00:00+00:00"}


def test_updated_cve_replaces_its_ranges_and_rejected_one_goes(tmp_path: Path) -> None:
    with _cache(tmp_path) as cache:
        sync(cache, _client(FakeNvd([NGINX]))[0])
        changed = copy.deepcopy(NGINX)
        changed["configurations"] = [{"nodes": [{"cpeMatch": [NGINX_MATCH]}]}]
        sync(cache, _client(FakeNvd([changed]))[0], full=True)
        (record,) = cache.records_for_product("nginx")
        assert [a.describe() for a in record.affects] == ["f5:nginx < 1.20.1"]
        assert cache.status().ranges == 1

        gone = copy.deepcopy(NGINX)
        gone["vulnStatus"] = "Rejected"
        sync(cache, _client(FakeNvd([gone]))[0], full=True)
        assert cache.status().cves == 0


def test_interrupted_sync_is_not_recorded_as_done(tmp_path: Path) -> None:
    fake = FakeNvd([NGINX, OPENSSH], failures=[])
    client, _ = _client(fake, page_size=1, retries=0)
    original = fake.__call__

    def fail_second(url: str, headers: dict[str, str]) -> Any:
        if len(fake.requests) == 1:
            fake.requests.append(({}, {}))
            raise _Retryable("connection reset")
        return original(url, headers)

    client.fetch = fail_second
    with _cache(tmp_path) as cache:
        with pytest.raises(NvdError):
            sync(cache, client)
        assert cache.status().cves == 1  # the first page is kept...
        assert cache.last_sync("all") is None  # ...but the next sync starts over


def test_cache_source_matches_like_the_seed_does(tmp_path: Path) -> None:
    with _cache(tmp_path) as cache:
        sync(
            cache,
            _client(FakeNvd([NGINX, OPENSSH]))[0],
            now=lambda: datetime(2026, 11, 22, tzinfo=UTC),
        )
        source = NvdCveSource(cache)
        assert source.name == "NVD cache (synced 2026-11-22)"
        ssh = Service(port=22, product="OpenSSH", version="7.4p1 Debian 10+deb9u7")
        (finding,) = source.find(ssh, "h")
        assert (finding.cve, finding.confidence) == ("CVE-2018-15473", Confidence.TENTATIVE)
        assert (
            "Affected per NVD cache (synced 2026-11-22): openbsd:openssh <= 7.7" in finding.evidence
        )
        nginx = Service(port=80, product="nginx", version="1.18.0", cpe="cpe:/a:igor_sysoev:nginx")
        assert [f.cve for f in source.find(nginx, "h")] == ["CVE-2021-23017"]
        assert source.find(Service(port=80, product="nginx", version="1.21.0"), "h") == []
