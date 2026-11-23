"""Which finding to fix first (G11).

Severity alone ranks by *how bad it could be*; most critical CVEs are never
exploited, and some medium ones are exploited every day. ZuesScan therefore ranks by
evidence of exploitation first, then by impact — the idea behind CISA's SSVC and the
"KEV first, then EPSS, then CVSS" practice:

    P1  act now     known exploited in the wild (in CISA's KEV catalog)
    P2  high        EPSS >= 10 %, or CVSS >= 9.0
    P3  medium      EPSS >= 1 %, or CVSS >= 7.0
    P4  low         everything else

Without a CVSS score, the severity stands in for it (critical 9.0, high 7.0, ...).
Confidence is shown next to the priority, not mixed into it: a tentative P1 is still
the first thing to check.
"""

from __future__ import annotations

from enum import StrEnum

from zues_scan.schema import Finding, Severity

EPSS_HIGH = 0.10
EPSS_MEDIUM = 0.01

_SEVERITY_SCORE = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 0.1,
    Severity.INFO: 0.0,
}


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


def score(finding: Finding) -> float:
    """The CVSS base score, or the severity's stand-in when there is none."""
    if finding.cvss_score is not None:
        return finding.cvss_score
    return _SEVERITY_SCORE[finding.severity]


def priority(finding: Finding) -> Priority:
    return rank(finding)[0]


def reason(finding: Finding) -> str:
    """Why the finding got its priority, in a few words."""
    return rank(finding)[1]


def rank(finding: Finding) -> tuple[Priority, str]:
    epss = finding.epss
    cvss = score(finding)
    source = "CVSS" if finding.cvss_score is not None else "severity"
    if finding.kev_added:
        return Priority.P1, f"known exploited (CISA KEV since {finding.kev_added})"
    if epss is not None and epss >= EPSS_HIGH:
        return Priority.P2, f"EPSS {epss:.0%}: likely to be exploited"
    if cvss >= 9.0:
        return Priority.P2, f"{source} {cvss:.1f}"
    if epss is not None and epss >= EPSS_MEDIUM:
        return Priority.P3, f"EPSS {epss:.1%}"
    if cvss >= 7.0:
        return Priority.P3, f"{source} {cvss:.1f}"
    return Priority.P4, f"{source} {cvss:.1f}" + (f", EPSS {epss:.1%}" if epss is not None else "")


def sort_key(finding: Finding) -> tuple[str, float, float]:
    """Most urgent first: priority, then exploitation probability, then impact."""
    return (str(priority(finding)), -(finding.epss or 0.0), -score(finding))
