"""CPE names — the shared vocabulary between scanners and vulnerability databases.

A CPE names a product: `cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*` is part "a"
(application), vendor "openbsd", product "openssh", version "7.4", update "p1".
nmap writes the older 2.2 URI form (`cpe:/a:openbsd:openssh:7.4`); NVD writes 2.3.
Both are read here into the same :class:`Cpe`.

Vendors are not spelled the same everywhere: nmap calls nginx's vendor
"igor_sysoev", NVD's newer entries say "f5" (which bought nginx). `same_vendor`
knows those few aliases; matching on the product name alone would confuse two
different products that happen to share a name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote


class CpeError(ValueError):
    """Not a CPE name ReconKit can read."""


@dataclass(frozen=True, slots=True)
class Cpe:
    part: str  # "a" application, "o" operating system, "h" hardware
    vendor: str
    product: str
    version: str | None = None  # None: any version ("*", or not given)
    update: str | None = None

    def __str__(self) -> str:
        fields = [self.part, self.vendor, self.product, self.version or "*", self.update or "*"]
        return "cpe:2.3:" + ":".join(fields) + ":*:*:*:*:*:*"


def parse_cpe(name: str) -> Cpe:
    """Read a CPE 2.3 formatted string or a CPE 2.2 URI."""
    text = name.strip()
    if text.startswith("cpe:2.3:"):
        # Split on ":" that is not escaped with a backslash.
        fields = [_unescape(f) for f in re.split(r"(?<!\\):", text[len("cpe:2.3:") :])]
        if len(fields) != 11:
            raise CpeError(f"a CPE 2.3 name has 11 fields after 'cpe:2.3:': {name!r}")
    elif text.startswith("cpe:/"):
        fields = [unquote(f) for f in text[len("cpe:/") :].split(":")]
    else:
        raise CpeError(f"not a CPE name: {name!r}")
    part, vendor, product = (fields + ["", "", ""])[:3]
    if part not in ("a", "o", "h") or not vendor or not product:
        raise CpeError(f"a CPE needs a part (a/o/h), a vendor and a product: {name!r}")
    version = fields[3] if len(fields) > 3 else None
    update = fields[4] if len(fields) > 4 else None
    return Cpe(
        part=part,
        vendor=vendor.lower(),
        product=product.lower(),
        version=_any(version),
        update=_any(update),
    )


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _any(value: str | None) -> str | None:
    """ "*" (any), "-" (not applicable) and "" all mean: no constraint here."""
    return None if value in (None, "", "*", "-") else value


# Vendors that name the same maker, per product. Only aliases seen in practice between
# nmap's service database and NVD are listed; add to it when a real mismatch shows up.
_VENDOR_ALIASES: dict[str, set[str]] = {
    "nginx": {"igor_sysoev", "f5", "nginx"},
    "vsftpd": {"vsftpd", "vsftpd_project", "beasts"},
    "mysql": {"mysql", "oracle"},
    "http_server": {"apache"},  # IBM / Oracle "http_server" are other products
    "openssh": {"openbsd"},
}


def same_vendor(product: str, a: str, b: str) -> bool:
    """Do vendors `a` and `b` name the same maker of `product`?"""
    if a == b:
        return True
    aliases = _VENDOR_ALIASES.get(product, set())
    return a in aliases and b in aliases


# nmap product names -> CPE (vendor, product), for when nmap printed a name but no
# CPE. A match found this way is less certain than one made on a CPE.
PRODUCT_NAMES: dict[str, tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "mysql": ("oracle", "mysql"),
    "proftpd": ("proftpd", "proftpd"),
    "postfix smtpd": ("postfix", "postfix"),
    "exim smtpd": ("exim", "exim"),
    "isc bind": ("isc", "bind"),
    "microsoft iis httpd": ("microsoft", "internet_information_services"),
    "apache tomcat": ("apache", "tomcat"),
    "postgresql db": ("postgresql", "postgresql"),
    "redis key-value store": ("redis", "redis"),
    "dovecot imapd": ("dovecot", "dovecot"),
    "samba smbd": ("samba", "samba"),
}
