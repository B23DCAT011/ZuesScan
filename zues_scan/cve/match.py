"""Match a scanned service against vulnerability records (G8, G10).

1. **Identify** the software: vendor + product from the CPE the scanner reported,
   else from its product name (a small table of nmap names); the version from the
   reported version string, taken apart into upstream release / patch level /
   distribution package (see :mod:`zues_scan.cve.version`).
2. **Compare** that upstream release with each affected range of the record, by
   number, not as text.
3. **Say how sure** the match is: a version match is an inference. On a
   distribution package it is *tentative* — distributions backport fixes and keep the
   upstream version number — otherwise *firm*. Only a check that exercises the flaw
   (a later plugin) can make a finding *confirmed*.

Only the product's own entry in a CVE's configuration is used; conditions such as
"... running on Debian 9" (NVD's AND-configurations) are not checked, since a port
scan does not see the operating system reliably. Such a match is still reported, but
the condition is one more reason it can be wrong.
"""

from __future__ import annotations

from dataclasses import dataclass

from zues_scan.cve.cpe import PRODUCT_NAMES, TECH_NAMES, CpeError, parse_cpe, same_vendor
from zues_scan.cve.records import AffectedRange, CveRecord
from zues_scan.cve.version import ReportedVersion, read_version
from zues_scan.schema import Confidence, Finding, Service


@dataclass(frozen=True, slots=True)
class Software:
    """What runs behind a port, as far as the scanner's report tells."""

    vendor: str
    product: str
    version: ReportedVersion
    via: str  # "cpe" or "product name": how vendor + product were found

    def describe(self) -> str:
        update = self.version.update or ""
        return f"{self.vendor}:{self.product} {self.version.release.text}{update}"


def identify(service: Service) -> Software | None:
    """The software behind `service`, or None if it cannot be pinned down.

    No version, no match: "OpenSSH, some version" would match every OpenSSH CVE ever.
    """
    context = service.banner or ""
    version = read_version(service.version, context)
    cpe = None
    if service.cpe:
        try:
            cpe = parse_cpe(service.cpe)
        except CpeError:
            cpe = None  # unreadable: fall back on the product name
    if cpe is not None:
        vendor, product, via = cpe.vendor, cpe.product, "cpe"
        if version is None and cpe.version:
            version = read_version(cpe.version, context)
    elif service.product and service.product.strip().lower() in PRODUCT_NAMES:
        vendor, product = PRODUCT_NAMES[service.product.strip().lower()]
        via = "product name"
    else:
        return None
    if version is None:
        return None
    return Software(vendor=vendor, product=product, version=version, via=via)


WEB_TECHNOLOGY = "web technology seen by httpx: "  # the banner of a component


def components(service: Service) -> list[Service]:
    """Software a web check saw behind `service` (httpx: "PHP:7.4.3"), as services on
    the same port, so the CVE stage matches them like any other. Without a version, or
    under a name not in `TECH_NAMES`, nothing is matched."""
    if service.web is None:
        return []
    found = []
    for tech in service.web.technologies:
        name, sep, version = tech.rpartition(":")
        name, version = name.strip(), version.strip()
        known = TECH_NAMES.get(name.lower()) if sep else None
        if known is None or not version or not version[0].isdigit():
            continue
        vendor, product = known
        found.append(
            Service(
                port=service.port,
                protocol=service.protocol,
                name=service.name,
                product=name,
                version=version,
                cpe=f"cpe:/a:{vendor}:{product}:{version}",
                banner=f"{WEB_TECHNOLOGY}{tech}",
            )
        )
    return found


def affected_range(software: Software, record: CveRecord) -> AffectedRange | None:
    """The range of `record` that `software` falls in, if any."""
    for candidate in record.affects:
        cpe = candidate.cpe
        if cpe.product != software.product:
            continue
        if not same_vendor(cpe.product, cpe.vendor, software.vendor):
            continue
        # An exact entry may name the patch level too ("9.9" + "p1"): then 9.9p2, the
        # fixed build, is not it. A range or an entry without one ignores patch levels.
        update = software.version.update
        if cpe.version is not None and cpe.update and update and cpe.update.lower() != update:
            continue
        if candidate.contains(software.version.release):
            return candidate
    return None


def confidence(software: Software) -> Confidence:
    return Confidence.TENTATIVE if software.version.distro else Confidence.FIRM


def to_finding(
    service: Service,
    asset_host: str,
    software: Software,
    record: CveRecord,
    matched: AffectedRange,
    source: str,
) -> Finding:
    return Finding(
        asset=asset_host,
        title=record.title or record.id,
        severity=record.severity,
        service=service,
        cve=record.id,
        description=record.description,
        evidence=evidence(service, software, matched, source),
        confidence=confidence(software),
        cvss_score=record.cvss_score,
        cvss_vector=record.cvss_vector,
        cwe=record.cwe,
        kev_added=record.kev_added,
        epss=record.epss,
    )


def evidence(service: Service, software: Software, matched: AffectedRange, source: str) -> str:
    """Say what was observed and why it matched, so that a person can re-check it."""
    if service.banner and service.banner.startswith(WEB_TECHNOLOGY):
        # A component: what httpx recognised in the HTTP answer, not a port scanner's word.
        tech = service.banner.removeprefix(WEB_TECHNOLOGY)
        observed = f"the web check (httpx) recognised {tech!r} in the HTTP answer"
    else:
        seen = [f"product {service.product!r}", f"version {service.version!r}"]
        if service.cpe:
            seen.append(f"cpe {service.cpe}")
        if service.banner:
            seen.append(f"banner {service.banner!r}")
        observed = f"scanner reported {', '.join(seen)}"
    text = (
        f"{service.port}/{service.protocol} {service.state}: {observed}. "
        f"Identified as {software.describe()} (from the {software.via}). "
        f"Affected per {source}: {matched.describe()}."
    )
    if software.version.distro:
        text += (
            " This is a distribution's package: the fix may have been backported without "
            "changing the version; check the distribution's security tracker."
        )
    return text + " Inferred from the version; not verified by exploitation."
