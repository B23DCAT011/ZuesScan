"""Tests for version reading, CPE names and range matching (G8, G10)."""

from pathlib import Path

import pytest

from zues_scan.cve import CveDataError, LocalCveSource
from zues_scan.cve.cpe import Cpe, CpeError, parse_cpe, same_vendor
from zues_scan.cve.records import AffectedRange, load_records
from zues_scan.cve.version import Version, read_version
from zues_scan.plugins.nmap import NmapPlugin
from zues_scan.schema import Confidence, Service

DATA = Path(__file__).parent / "data"

# --- Version ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("7.9", "7.10"),  # numbers, not text
        ("1.18.0", "1.20.1"),
        ("0.6.18", "1.0"),
        ("1.0rc1", "1.0"),  # a release candidate comes before the release
        ("1.0beta2", "1.0rc1"),
        ("1.0", "1.0.1"),
        ("1.0.2k", "1.0.2l"),  # OpenSSL letter releases
        ("1.0.2", "1.0.2a"),
        ("2.4.9", "2.4.49"),
    ],
)
def test_versions_compare_like_a_person_would(low: str, high: str) -> None:
    assert Version(low) < Version(high)
    assert Version(high) > Version(low)


def test_trailing_zeros_do_not_matter() -> None:
    assert Version("1.0") == Version("1.0.0")
    assert hash(Version("1.0")) == hash(Version("1.0.0"))


@pytest.mark.parametrize("text", ["", " ", "-1", "(unknown)"])
def test_not_a_version(text: str) -> None:
    with pytest.raises(ValueError):
        Version(text)


@pytest.mark.parametrize(
    ("raw", "context", "release", "update", "distro"),
    [
        ("7.4p1 Debian 10+deb9u7", "", "7.4", "p1", True),
        ("8.2p1 Ubuntu 4ubuntu0.5", "", "8.2", "p1", True),
        ("7.4", "protocol 2.0", "7.4", None, False),
        ("2.4.6", "(CentOS)", "2.4.6", None, True),  # Apache puts the distro in extrainfo
        ("2.4.29-1ubuntu4.14", "", "2.4.29", None, True),
        ("5.7.42-0ubuntu0.18.04.1", "", "5.7.42", None, True),
        ("1.18.0", "", "1.18.0", None, False),
        ("9.6p1", "", "9.6", "p1", False),
    ],
)
def test_reported_version_is_taken_apart(
    raw: str, context: str, release: str, update: str | None, distro: bool
) -> None:
    reported = read_version(raw, context)
    assert reported is not None
    assert reported.release == Version(release)
    assert (reported.update, reported.distro) == (update, distro)


@pytest.mark.parametrize("raw", [None, "", "   ", "(unknown)"])
def test_no_version_in_the_report(raw: str | None) -> None:
    assert read_version(raw) is None


# --- CPE --------------------------------------------------------------------------------


def test_cpe_2_2_uri_from_nmap() -> None:
    assert parse_cpe("cpe:/a:openbsd:openssh:7.4p1") == Cpe("a", "openbsd", "openssh", "7.4p1")
    assert parse_cpe("cpe:/a:apache:http_server") == Cpe("a", "apache", "http_server")


def test_cpe_2_3_from_nvd() -> None:
    cpe = parse_cpe("cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*")
    assert (cpe.vendor, cpe.product, cpe.version, cpe.update) == (
        "openbsd",
        "openssh",
        "7.4",
        "p1",
    )
    assert parse_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*").version is None
    escaped = parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert escaped.product == "prod:uct"


@pytest.mark.parametrize("name", ["", "openssh", "cpe:2.3:a:x", "cpe:/x:a:b", "cpe:/a::b"])
def test_bad_cpe(name: str) -> None:
    with pytest.raises(CpeError):
        parse_cpe(name)


def test_vendor_aliases_are_per_product() -> None:
    assert same_vendor("nginx", "igor_sysoev", "f5")
    assert same_vendor("vsftpd", "vsftpd", "vsftpd_project")
    assert not same_vendor("http_server", "apache", "ibm")  # IBM HTTP Server: another product
    assert not same_vendor("openssh", "openbsd", "f5")


# --- ranges -----------------------------------------------------------------------------


def _nginx(**bounds: str) -> AffectedRange:
    return AffectedRange(cpe=parse_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"), **bounds)


def test_range_bounds() -> None:
    nginx = _nginx(start_including="0.6.18", end_excluding="1.20.1")
    assert nginx.contains(Version("1.18.0"))
    assert nginx.contains(Version("0.6.18"))
    assert not nginx.contains(Version("1.20.1"))
    assert not nginx.contains(Version("0.6.17"))
    assert _nginx(end_including="7.7").contains(Version("7.7"))
    assert not _nginx(start_excluding="1.0").contains(Version("1.0"))


def test_unbounded_range_matches_nothing() -> None:
    # NVD's "every version" entries come from unanalysed products: they prove nothing.
    assert not _nginx().contains(Version("1.18.0"))


# --- matching services --------------------------------------------------------------------


def _cves(service: Service) -> list[str | None]:
    return [f.cve for f in LocalCveSource().find(service, "h")]


def test_distro_build_matches_on_its_upstream_version_but_tentatively() -> None:
    # The very string nmap reports for OpenSSH on Debian 9 (G8: it used to match nothing).
    (finding,) = LocalCveSource().find(
        Service(port=22, product="OpenSSH", version="7.4p1 Debian 10+deb9u7"), "h"
    )
    assert finding.cve == "CVE-2018-15473"
    assert finding.confidence == Confidence.TENTATIVE
    assert "backported" in finding.evidence
    assert "openbsd:openssh <= 7.7" in finding.evidence


def test_upstream_build_in_range_is_firm() -> None:
    svc = Service(port=22, product="OpenSSH", version="7.7p1", cpe="cpe:/a:openbsd:openssh:7.7p1")
    (finding,) = LocalCveSource().find(svc, "h")
    assert finding.confidence == Confidence.FIRM
    assert "(from the cpe)" in finding.evidence


def test_version_outside_the_range_does_not_match() -> None:
    assert _cves(Service(port=22, product="OpenSSH", version="7.8p1")) == []
    assert _cves(Service(port=80, product="nginx", version="1.20.1")) == []


def test_any_version_in_a_range_matches_not_just_one() -> None:
    assert _cves(Service(port=80, product="nginx", version="1.14.2")) == ["CVE-2021-23017"]


def test_vendor_spelt_differently_by_nmap_still_matches() -> None:
    # nmap: igor_sysoev:nginx; NVD: f5:nginx. nmap: vsftpd:vsftpd; NVD: vsftpd_project.
    nginx = Service(
        port=80, product="nginx", version="1.18.0", cpe="cpe:/a:igor_sysoev:nginx:1.18.0"
    )
    ftp = Service(port=21, product="vsftpd", version="2.3.4", cpe="cpe:/a:vsftpd:vsftpd:2.3.4")
    assert _cves(nginx) == ["CVE-2021-23017"]
    assert _cves(ftp) == ["CVE-2011-2523"]


def test_same_product_name_from_another_vendor_does_not_match() -> None:
    ibm = Service(port=80, version="2.4.49", cpe="cpe:/a:ibm:http_server:2.4.49")
    assert _cves(ibm) == []


def test_version_from_the_cpe_when_nmap_gave_none() -> None:
    svc = Service(port=80, product="Apache httpd", cpe="cpe:/a:apache:http_server:2.4.49")
    assert _cves(svc) == ["CVE-2021-41773"]


def test_no_version_no_match() -> None:
    assert _cves(Service(port=80, product="Apache httpd", cpe="cpe:/a:apache:http_server")) == []


def test_unreadable_cpe_falls_back_on_the_product_name() -> None:
    svc = Service(port=80, product="nginx", version="1.18.0", cpe="garbage")
    (finding,) = LocalCveSource().find(svc, "h")
    assert "(from the product name)" in finding.evidence


def test_matches_found_in_a_realistic_nmap_scan() -> None:
    xml = (DATA / "nmap_real_versions.xml").read_text(encoding="utf-8")
    (asset,) = NmapPlugin.parse_xml(xml)
    source = LocalCveSource()
    found = {
        (s.port, f.cve, f.confidence) for s in asset.services for f in source.find(s, asset.host)
    }
    assert found == {
        (22, "CVE-2018-15473", Confidence.TENTATIVE),  # OpenSSH 7.4p1 Debian 10+deb9u7
        (21, "CVE-2011-2523", Confidence.FIRM),  # vsftpd 2.3.4
        (80, "CVE-2021-23017", Confidence.TENTATIVE),  # nginx 1.14.2 (Debian)
    }  # Apache 2.4.62 is past the seed's range; MySQL is not in the seed


# --- data files -----------------------------------------------------------------------------


def test_bundled_seed_is_valid() -> None:
    records = load_records(Path(__file__).parent.parent / "zues_scan" / "data" / "cve_seed.json")
    assert {r.id for r in records} >= {"CVE-2018-15473", "CVE-2021-41773"}
    assert all(a.is_bounded() for r in records for a in r.affects)


_V2 = '{"format": "zues-cve", "version": 2, "entries": '


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"entries": [{"product": "openssh", "version": "7.4"}]}', "old format"),
        ('{"format": "zues-cve", "version": 9, "entries": []}', "expected"),
        (_V2 + '[{"cve": "X"}]}', "missing"),
        (_V2 + '[{"cve": "X", "affects": [{"cpe": "nope"}]}]}', "not a CPE"),
        (
            _V2 + '[{"cve": "X", "affects": [{"cpe": "cpe:2.3:a:a:b:*:*:*:*:*:*:*:*", '
            '"versionEndExcluding": "-"}]}]}',
            "not a version",
        ),
        ("not json", "cannot read"),
    ],
)
def test_bad_data_file_is_refused(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "cves.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CveDataError, match=message):
        LocalCveSource(path)


def test_missing_data_file(tmp_path: Path) -> None:
    with pytest.raises(CveDataError, match="not found"):
        LocalCveSource(tmp_path / "nope.json")
