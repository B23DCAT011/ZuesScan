"""NVD API 2.0 client: download CVE records, politely (G9).

https://nvd.nist.gov/developers/vulnerabilities — the public CVE API of NIST.

* Paged: up to 2,000 CVEs per request (`startIndex`, `resultsPerPage`).
* Rate-limited by NVD: without an API key, 5 requests per rolling 30 seconds; with
  one, 50. ZuesScan waits 6 s (1 s with a key) between requests and backs off on
  403 / 429 / 5xx, as NVD asks.
* Incremental: `lastModStartDate` / `lastModEndDate` fetch only what changed, in
  windows of at most 120 days (an NVD limit).
* `virtualMatchString` limits a download to one product (a CPE prefix), for a
  small cache or a quick test.

The API key is read from the `NVD_API_KEY` environment variable, never from the
command line, where it would end up in shell history and process lists.

Only the Python standard library is used (`urllib`). The transport is injectable,
so tests run against canned pages without any network.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from zues_scan import __version__
from zues_scan.cve.cpe import CpeError, parse_cpe
from zues_scan.cve.records import AffectedRange, CveRecord
from zues_scan.cve.version import Version
from zues_scan.schema import Severity

log = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
API_KEY_ENV = "NVD_API_KEY"

# (url, headers) -> parsed JSON; raises NvdError (or the retryable kind) on failure.
Fetch = Callable[[str, dict[str, str]], Any]


class NvdError(Exception):
    """The NVD API could not be used (network, rate limit, bad answer)."""


class _Retryable(NvdError):
    pass


def http_fetch(url: str, headers: dict[str, str], timeout: float = 60) -> Any:
    """GET `url` and parse its JSON body. Errors worth retrying raise `_Retryable`."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # NVD answers 403 when the rate limit is hit (and for a bad key), 503 when busy.
        if exc.code in (403, 429) or exc.code >= 500:
            raise _Retryable(f"NVD answered HTTP {exc.code} for {url}") from exc
        raise NvdError(f"NVD answered HTTP {exc.code} for {url}") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise _Retryable(f"cannot reach NVD: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _Retryable(f"NVD sent an unreadable answer: {exc}") from exc


@dataclass
class NvdClient:
    """Pages through the NVD CVE API, respecting its rate limits."""

    api_key: str | None = None
    fetch: Fetch = http_fetch
    sleep: Callable[[float], None] = time.sleep
    retries: int = 5
    page_size: int = PAGE_SIZE

    @property
    def delay(self) -> float:
        """Seconds between two requests: NVD's limit, with a margin."""
        return 1.0 if self.api_key else 6.0

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": f"zues-scan/{__version__}", "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _get(self, params: dict[str, str]) -> dict[str, Any]:
        url = f"{API_URL}?{urllib.parse.urlencode(params)}"  # the API key is a header, not here
        for attempt in range(self.retries + 1):
            log.debug("GET %s", url, extra={"event": "nvd.request"})
            try:
                data = self.fetch(url, self._headers())
            except _Retryable as exc:
                if attempt == self.retries:
                    log.error("NVD: giving up after %d attempts: %s", attempt + 1, exc)
                    raise
                wait = min(self.delay * 2 ** (attempt + 1), 120)
                log.warning("NVD: %s; retrying in %.0f s", exc, wait, extra={"event": "nvd.retry"})
                self.sleep(wait)  # back off
                continue
            if not isinstance(data, dict) or "vulnerabilities" not in data:
                raise NvdError(f"unexpected answer from NVD for {url}")
            return data
        raise NvdError("unreachable")  # pragma: no cover

    def pages(
        self,
        *,
        product: str | None = None,
        modified_since: datetime | None = None,
        until: datetime | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> Iterator[list[dict[str, Any]]]:
        """Yield the CVEs, one page (a list of NVD `cve` objects) at a time.

        `product` is a CPE prefix (e.g. "cpe:2.3:a:openbsd:openssh"); `modified_since`
        limits the download to CVEs changed since then.
        """
        windows: list[tuple[datetime, datetime] | None] = [None]
        if modified_since is not None:
            end = until or datetime.now(UTC)
            windows = []
            start = modified_since
            while start < end:
                stop = min(start + MAX_WINDOW, end)
                windows.append((start, stop))
                start = stop
        first = True
        for window in windows:
            index, total = 0, None
            while total is None or index < total:
                params = {"startIndex": str(index), "resultsPerPage": str(self.page_size)}
                if product:
                    params["virtualMatchString"] = product
                if window is not None:
                    params["lastModStartDate"] = _nvd_time(window[0])
                    params["lastModEndDate"] = _nvd_time(window[1])
                if not first:
                    self.sleep(self.delay)
                first = False
                data = self._get(params)
                total = int(data.get("totalResults", 0))
                page = [v["cve"] for v in data["vulnerabilities"] if "cve" in v]
                index += len(page)
                if progress is not None:
                    progress(index, total)
                yield page
                if not page:
                    break  # NVD said there is more but sent nothing: do not loop forever


def _nvd_time(moment: datetime) -> str:
    """ISO-8601 the way NVD wants it, e.g. 2026-11-22T12:00:00.000Z."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# --- turning an NVD `cve` object into a record -------------------------------------------

# Which CVSS to trust first: NVD's own (Primary) score, newest stable version first.
_METRICS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


@dataclass(frozen=True, slots=True)
class NvdEntry:
    """What the cache keeps of one NVD CVE."""

    record: CveRecord
    published: str | None
    last_modified: str | None
    status: str
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cwe: tuple[str, ...]


def parse_cve(cve: dict[str, Any]) -> NvdEntry | None:
    """Read one NVD `cve` object; None if it is rejected or has no usable data."""
    status = str(cve.get("vulnStatus", ""))
    cve_id = cve.get("id")
    if not cve_id or status == "Rejected":
        return None
    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    version, score, vector, severity = _cvss(cve.get("metrics", {}))
    cwes = _cwe(cve.get("weaknesses", []))
    return NvdEntry(
        record=CveRecord(
            id=str(cve_id),
            severity=severity,
            affects=tuple(_ranges(cve.get("configurations", []))),
            title=title_from(description),
            description=description,
            cvss_score=score,
            cvss_vector=vector,
            cwe=cwes,
            # NVD copies CISA's KEV listing into the record.
            kev_added=cve.get("cisaExploitAdd") or None,
        ),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        status=status,
        cvss_version=version,
        cvss_score=score,
        cvss_vector=vector,
        cwe=cwes,
    )


def _cvss(metrics: dict[str, Any]) -> tuple[str | None, float | None, str | None, Severity]:
    for key in _METRICS:
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            label = data.get("baseSeverity") or entry.get("baseSeverity") or ""
            return data.get("version"), float(score), data.get("vectorString"), _severity(label)
    return None, None, None, Severity.INFO


def _severity(label: str) -> Severity:
    return {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    }.get(label.upper(), Severity.INFO)


def _cwe(weaknesses: list[dict[str, Any]]) -> tuple[str, ...]:
    found: list[str] = []
    for weakness in weaknesses:
        for d in weakness.get("description", []):
            value = str(d.get("value", ""))
            # "NVD-CWE-Other" / "NVD-CWE-noinfo" say there is no CWE.
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return tuple(found)


def _ranges(configurations: list[dict[str, Any]]) -> Iterator[AffectedRange]:
    """The vulnerable product entries of a CVE's configurations.

    Nodes that are negated ("not running on ...") are skipped; the platform half of an
    AND configuration is kept as its own entry, as NVD marks it (see match.py).
    """
    seen: set[AffectedRange] = set()
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                try:
                    cpe = parse_cpe(str(match.get("criteria", "")))
                    bounds = {
                        key: match.get(key)
                        for key in (
                            "versionStartIncluding",
                            "versionStartExcluding",
                            "versionEndIncluding",
                            "versionEndExcluding",
                        )
                    }
                    for value in bounds.values():
                        if value is not None:
                            Version(str(value))
                    if cpe.version is not None:
                        Version(cpe.version)
                except (CpeError, ValueError):
                    continue  # unreadable: skipped rather than guessed at
                found = AffectedRange(
                    cpe=cpe,
                    start_including=bounds["versionStartIncluding"],
                    start_excluding=bounds["versionStartExcluding"],
                    end_including=bounds["versionEndIncluding"],
                    end_excluding=bounds["versionEndExcluding"],
                )
                if found.is_bounded() and found not in seen:
                    seen.add(found)
                    yield found


def title_from(description: str, limit: int = 90) -> str:
    """A short label from an NVD description (NVD records have no title)."""
    first = description.strip().split(". ")[0].rstrip(".")
    if len(first) <= limit:
        return first
    cut = first[: limit - 1]
    cut = cut.rsplit(" ", 1)[0] if " " in cut else cut  # end on a whole word
    return cut.rstrip(" ,;:") + "…"
