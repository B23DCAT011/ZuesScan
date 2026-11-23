"""Debian packages: versions, installed lists, and the Debian Security Tracker.

An authenticated scan (G10's real fix) does not guess from a banner: it asks the
machine which packages are installed (`dpkg-query`) and compares each one with the
Debian Security Tracker, which says, per source package and release, whether a CVE is
fixed and in which package version — backports included. "OpenSSH 9.2p1" in a banner
says little; "openssh 1:9.2p1-2+deb12u3 installed, CVE fixed in 1:9.2p1-2+deb12u3"
settles it.

Pure functions; the SSH plugin and the cache call them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"

# --- Debian version comparison (Debian Policy 5.6.12) ---------------------------------------


def _order(char: str) -> int:
    """Sort weight of one non-digit character: ~ before end, letters before symbols."""
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    """Compare an upstream version or a revision, the dpkg way."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit prefix, character by character ("~" sorts before everything).
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            cb = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ca != cb:
                return -1 if ca < cb else 1
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
        # Digit run, as a number.
        start_i, start_j = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        na, nb = int(a[start_i:i] or 0), int(b[start_j:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def split_version(version: str) -> tuple[int, str, str]:
    """`[epoch:]upstream[-revision]` -> (epoch, upstream, revision)."""
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    upstream, _, revision = version.rpartition("-")
    if not upstream:  # no "-": a native package, no revision
        upstream, revision = revision, ""
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1, as `dpkg --compare-versions` would order `a` and `b`."""
    ea, ua, ra = split_version(a.strip())
    eb, ub, rb = split_version(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)


# --- what the machine says -----------------------------------------------------------------------

# The command run over SSH: fixed text, nothing from the scan goes into it.
REMOTE_COMMAND = (
    "cat /etc/os-release; echo '---ZUES---'; "
    "dpkg-query -W -f='${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n'"
)
SEPARATOR = "---ZUES---"


@dataclass(frozen=True, slots=True)
class OsRelease:
    id: str  # "debian"
    version_id: str  # "12"
    codename: str  # "bookworm"
    pretty: str


@dataclass(frozen=True, slots=True)
class Package:
    name: str  # binary package, e.g. "openssh-server"
    version: str
    source: str  # source package, what the tracker speaks about, e.g. "openssh"
    source_version: str


def parse_os_release(text: str) -> OsRelease:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return OsRelease(
        id=values.get("ID", "").lower(),
        version_id=values.get("VERSION_ID", ""),
        codename=values.get("VERSION_CODENAME", "").lower(),
        pretty=values.get("PRETTY_NAME", ""),
    )


def parse_dpkg(text: str) -> list[Package]:
    packages = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0] or not fields[1]:
            continue  # "not installed" rows have no version
        name = fields[0].split(":")[0]  # drop the ":amd64" architecture
        source = (fields[2] if len(fields) > 2 and fields[2] else name).split(" ")[0]
        source_version = fields[3] if len(fields) > 3 and fields[3] else fields[1]
        packages.append(Package(name, fields[1], source, source_version))
    return packages


def parse_remote(text: str) -> tuple[OsRelease, list[Package]]:
    head, sep, tail = text.partition(SEPARATOR)
    if not sep:
        raise ValueError("unexpected answer: no package list")
    return parse_os_release(head), parse_dpkg(tail)


# --- the tracker ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrackerEntry:
    source: str
    cve: str
    release: str
    status: str  # "resolved", "open", "undetermined"
    fixed_version: str | None  # "0": never affected in this release
    urgency: str
    description: str


def iter_tracker(text: str, releases: set[str]) -> Iterator[TrackerEntry]:
    """Read the tracker JSON one source package at a time, keeping `releases` only.

    The file is ~90 MB: decoding it whole would hold every package of every release in
    memory at once. Instead each top-level value is decoded separately.
    """
    decoder = json.JSONDecoder()
    pos = _skip(text, 0)
    if pos >= len(text) or text[pos] != "{":
        raise ValueError("the tracker data is not a JSON object")
    pos = _skip(text, pos + 1)
    while pos < len(text) and text[pos] != "}":
        source, pos = decoder.raw_decode(text, pos)
        pos = _skip(text, pos)
        if text[pos] != ":":
            raise ValueError(f"malformed tracker data near position {pos}")
        value, pos = decoder.raw_decode(text, _skip(text, pos + 1))
        yield from _entries(str(source), value, releases)
        pos = _skip(text, pos)
        if pos < len(text) and text[pos] == ",":
            pos = _skip(text, pos + 1)


def _skip(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def _entries(source: str, cves: object, releases: set[str]) -> Iterator[TrackerEntry]:
    if not isinstance(cves, dict):
        return
    for cve, data in cves.items():
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve)) or not isinstance(data, dict):
            continue  # also "TEMP-..." ids, which have no CVE yet
        for release, info in (data.get("releases") or {}).items():
            if release in releases and isinstance(info, dict):
                yield TrackerEntry(
                    source=source,
                    cve=str(cve),
                    release=str(release),
                    status=str(info.get("status", "")),
                    fixed_version=info.get("fixed_version"),
                    urgency=str(info.get("urgency", "")),
                    description=str(data.get("description", "")),
                )


def verdict(installed: str, entry: TrackerEntry) -> str | None:
    """Why `installed` (a source version) is affected by `entry`, or None if it is not."""
    if entry.status == "resolved":
        fixed = entry.fixed_version
        if not fixed or fixed == "0":
            return None  # this release never shipped the flaw
        if compare_versions(installed, fixed) < 0:
            return f"fixed in {fixed}: upgrade"
        return None
    if entry.status == "open":
        return "no fix released yet for this release"
    if entry.status == "undetermined":
        return "not yet assessed by Debian"
    return None
