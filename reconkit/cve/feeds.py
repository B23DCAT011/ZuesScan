"""Exploitation signals: CISA KEV and FIRST EPSS (G11).

CVSS says how bad a flaw *could* be; these two say how likely it is to be *used*:

* **KEV** — CISA's catalog of Known Exploited Vulnerabilities: CVEs seen exploited
  in the wild. Downloaded from CISA's official mirror on GitHub (cisagov/kev-data);
  www.cisa.gov refuses automated clients.
* **EPSS** — FIRST's Exploit Prediction Scoring System: for every CVE, the
  probability (0-1) that it is exploited in the next 30 days, recomputed daily.
  One gzipped CSV of all CVEs (~3 MB).

Both are public data, fetched with the standard library only. The transport is
injectable, so tests use canned files.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from reconkit import __version__

log = logging.getLogger(__name__)

KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_FEED_BYTES = 100 * 1024 * 1024  # far above today's sizes; refuses a runaway download

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")

FetchBytes = Callable[[str], bytes]


class FeedError(Exception):
    """A feed could not be downloaded or read."""


def http_get(url: str, timeout: float = 120) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": f"reconkit/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data: bytes = response.read(MAX_FEED_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise FeedError(f"cannot download {url}: {exc}") from exc
    if len(data) > MAX_FEED_BYTES:
        raise FeedError(f"{url} is larger than {MAX_FEED_BYTES} bytes; refusing it")
    log.info("downloaded %s (%d bytes)", url, len(data), extra={"event": "feed.download"})
    return data


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve: str
    added: str  # date CISA added it, YYYY-MM-DD
    due: str | None  # remediation deadline for US federal agencies
    ransomware: bool  # "knownRansomwareCampaignUse": "Known"
    name: str


def parse_kev(data: bytes) -> tuple[str, list[KevEntry]]:
    """Read the KEV catalog; return (catalog version, entries)."""
    try:
        catalog = json.loads(data.decode("utf-8"))
        entries = [
            KevEntry(
                cve=str(v["cveID"]).strip().upper(),
                added=str(v["dateAdded"]),
                due=v.get("dueDate"),
                ransomware=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                name=str(v.get("vulnerabilityName", "")),
            )
            for v in catalog["vulnerabilities"]
        ]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise FeedError(f"the KEV catalog is not in the expected format: {exc}") from exc
    entries = [e for e in entries if _CVE_ID.fullmatch(e.cve)]
    if not entries:
        raise FeedError("the KEV catalog lists no CVE; refusing to replace the known one")
    return str(catalog.get("catalogVersion", "?")), entries


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve: str
    score: float  # probability of exploitation in the next 30 days
    percentile: float  # share of CVEs with a lower score


def parse_epss(data: bytes) -> tuple[str | None, list[EpssScore]]:
    """Read FIRST's daily EPSS file (gzipped CSV); return (score date, scores)."""
    try:
        text = gzip.decompress(data).decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise FeedError(f"the EPSS file is not a readable gzip: {exc}") from exc
    lines = io.StringIO(text)
    first = lines.readline()
    # "#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z"
    match = re.search(r"score_date:(\S+)", first)
    if not first.startswith("#"):
        lines.seek(0)
    scores = list(_epss_rows(csv.DictReader(lines)))
    if not scores:
        raise FeedError("the EPSS file has no scores; refusing to replace the known ones")
    return (match.group(1) if match else None), scores


def _epss_rows(reader: csv.DictReader[str]) -> Iterator[EpssScore]:
    for row in reader:
        try:
            cve = row["cve"].strip().upper()
            score, percentile = float(row["epss"]), float(row["percentile"])
        except (KeyError, ValueError, AttributeError):
            continue
        if _CVE_ID.fullmatch(cve) and 0 <= score <= 1 and 0 <= percentile <= 1:
            yield EpssScore(cve=cve, score=score, percentile=percentile)
