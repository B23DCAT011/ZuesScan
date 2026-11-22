"""Software versions: read what a scanner reports, compare like a person would.

Two problems with comparing version *strings* (G8):

* "7.10" > "7.9" numerically, but not as text.
* a scanner reports what the software says about itself, e.g. OpenSSH on Debian
  answers "7.4p1 Debian 10+deb9u7": upstream release 7.4, portable patch level p1,
  then the distribution's own package revision. Vulnerability data speaks about the
  upstream release only.

:func:`read_version` splits the reported string into those parts, and
:class:`Version` compares upstream versions piece by piece: numbers as numbers,
letters as letters, a pre-release ("1.0rc1") before its release ("1.0").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

# Words that mark a version as coming *before* the release they precede.
_PRE_RELEASE = {"dev", "alpha", "beta", "pre", "preview", "rc", "snapshot"}

# Signs that a version is a distribution's package of the software, e.g.
# "Debian 10+deb9u7", "4ubuntu0.5", "1.el7", "(CentOS)". Distributions backport
# security fixes without changing the upstream version (G10).
_DISTRO = re.compile(
    r"\b(debian|ubuntu|raspbian|centos|red ?hat|rhel|fedora|suse|opensuse|alpine|"
    r"amazon linux|oracle linux|rocky|almalinux|freebsd|openbsd|netbsd)\b"
    r"|[+~.]deb\d|\d(?:ubuntu|build)\d|\.el\d|\.fc\d\d|\.amzn\d",
    re.IGNORECASE,
)

# OpenSSH-style portable patch level: "7.4p1" = release 7.4, patch level p1. NVD
# stores it the same way, as version "7.4" + update "p1".
_UPDATE = re.compile(r"^(?P<release>\d+(?:\.\d+)*)(?P<update>p\d+)$", re.IGNORECASE)

_TOKEN = re.compile(r"\d+|[a-z]+", re.IGNORECASE)


@total_ordering
class Version:
    """An upstream version, comparable to another: `Version("7.10") > Version("7.9")`."""

    __slots__ = ("text", "_key")

    def __init__(self, text: str) -> None:
        self.text = text.strip()
        if not self.text or not self.text[0].isalnum():
            raise ValueError(f"not a version: {text!r}")
        self._key = tuple(
            (0, int(t), "") if t.isdigit() else (1, 0, t.lower()) for t in _TOKEN.findall(self.text)
        )

    def _compare(self, other: Version) -> int:
        a, b = self._key, other._key
        for x, y in zip(a, b, strict=False):
            if x == y:
                continue
            if x[0] == y[0]:
                return -1 if x < y else 1
            # A number against a word: "1.0.1" vs "1.0rc1". The word is a
            # pre-release (before) or a letter release like "1.0a" (after the number's
            # position is filled, so: before a number).
            return 1 if x[0] == 0 else -1
        if len(a) == len(b):
            return 0
        longer, sign = (a, 1) if len(a) > len(b) else (b, -1)
        extra = longer[min(len(a), len(b))]
        # "1.0rc1" < "1.0" < "1.0.1" and "1.0a" (OpenSSL-style letter release).
        if extra[0] == 1 and extra[2] in _PRE_RELEASE:
            return -sign
        if extra == (0, 0, "") and all(t == (0, 0, "") for t in longer[min(len(a), len(b)) :]):
            return 0  # "1.0" == "1.0.0"
        return sign

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._compare(other) == 0

    def __lt__(self, other: Version) -> bool:
        return self._compare(other) < 0

    def __hash__(self) -> int:
        key = list(self._key)
        while key and key[-1] == (0, 0, ""):
            key.pop()
        return hash(tuple(key))

    def __repr__(self) -> str:
        return f"Version({self.text!r})"


@dataclass(frozen=True, slots=True)
class ReportedVersion:
    """What a scanner's version string says, taken apart."""

    raw: str  # exactly as reported, e.g. "7.4p1 Debian 10+deb9u7"
    release: Version  # the upstream release, e.g. 7.4
    update: str | None  # e.g. "p1"
    distro: bool  # a distribution package: fixes may be backported


def read_version(raw: str | None, context: str = "") -> ReportedVersion | None:
    """Take a reported version apart; None if it does not start with a version.

    `context` is other text the scanner printed about the service (its banner,
    "extra info"): distributions often show up there, e.g. Apache's "(CentOS)".
    """
    if not raw or not raw.strip():
        return None
    first = raw.strip().split()[0]
    # A trailing "-1ubuntu2" or "+deb9u7" glued to the version belongs to the package.
    upstream = re.split(r"[+~]|-(?=\d*(?:ubuntu|deb|el|fc)\d)", first, maxsplit=1)[0]
    update = None
    match = _UPDATE.match(upstream)
    if match:
        upstream, update = match.group("release"), match.group("update").lower()
    try:
        release = Version(upstream)
    except ValueError:
        return None
    distro = bool(_DISTRO.search(f"{raw} {context}"))
    return ReportedVersion(raw=raw.strip(), release=release, update=update, distro=distro)
