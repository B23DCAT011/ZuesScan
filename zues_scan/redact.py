"""Masking what a scanned machine gave away before ZuesScan keeps it (G24).

A check that confirms a flaw keeps the exchange as evidence: nuclei's request and response.
That proves the finding, and it also carries the target's data — session cookies, tokens,
password hashes, the file a path traversal read. The database is sensitive anyway (it maps
an organisation's weaknesses), but keeping secrets that are not needed to prove anything
only adds to what a leak of it would expose. So, before raw output is stored and hashed
into the audit trail:

- in HTTP headers, the values of credentials and sessions are masked (`Authorization`,
  `Cookie` / `Set-Cookie` — names kept, values masked —, and any header whose name says
  token, secret, key, session, password or auth);
- a response body is cut to `MAX_BODY` characters (the part that matched comes first in
  practice: the status, the headers, the beginning of the content), with a note of how
  much was left out;
- in all text, values that look like secrets are masked: `password=...`-style pairs, bearer
  tokens and JWTs, AWS keys, PEM private keys, crypt(3) password hashes (`/etc/shadow`),
  and the password in `scheme://user:password@host`.

What remains still shows what was sent and what came back. Masking is a best effort on
patterns — a secret in an unusual shape can get through — and the evidence is no
substitute for protecting the database (G24). Standard library only.
"""

from __future__ import annotations

import json
import re
from typing import Any

MASK = "[redacted]"
MAX_BODY = 2048

_SENSITIVE_HEADER = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|"
    r"x-csrf-token|x-xsrf-token|.*(token|secret|passw|session|api-?key|auth).*)$",
    re.IGNORECASE,
)
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys, whole.
    (
        re.compile(
            r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----", re.DOTALL
        ),
        f"-----BEGIN PRIVATE KEY----- {MASK} -----END PRIVATE KEY-----",
    ),
    # JSON Web Tokens (three base64url parts, the first a JSON header).
    (re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}"), MASK),
    # AWS access key ids.
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    # crypt(3) hashes, as in /etc/shadow: $id$salt$hash.
    (re.compile(r"\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:$]*\$[./A-Za-z0-9]{8,}"), MASK),
    # Passwords in URLs.
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@", re.IGNORECASE), rf"\1{MASK}@"),
    # Bearer / Basic credentials anywhere.
    (re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE), rf"\1 {MASK}"),
    # key = value pairs whose key names a secret (config files, query strings, JSON).
    (
        re.compile(
            r"""(["']?\b[\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key|"""
            r"""private[_-]?key|client[_-]?secret)[\w.-]*["']?\s*[:=]\s*["']?)"""
            r"""([^\s"'&,;}<]{3,})""",
            re.IGNORECASE,
        ),
        rf"\1{MASK}",
    ),
]


def text(value: str) -> str:
    """`value` with what looks like a secret masked."""
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def http(message: str, *, body_limit: int | None = None) -> str:
    """An HTTP request or response: credentials in its headers masked, its body cut to
    `body_limit` characters (None: kept whole), secrets in what remains masked."""
    head, separator, body = _split(message)
    lines = head.split("\n")
    kept = [lines[0]] if lines else []
    for line in lines[1:]:
        end = "\r" if line.endswith("\r") else ""  # the message's own line endings stay
        name, colon, value = line.removesuffix("\r").partition(":")
        if colon and _SENSITIVE_HEADER.match(name.strip()):
            kept.append(f"{name}:{_mask_header(name.strip(), value)}{end}")
        else:
            kept.append(line)
    if body_limit is not None and len(body) > body_limit:
        left = len(body) - body_limit
        body = body[:body_limit] + f"\n[... {left} more characters not kept: G24]"
    return text("\n".join(kept) + separator + body)


def _split(message: str) -> tuple[str, str, str]:
    for separator in ("\r\n\r\n", "\n\n"):
        head, found, body = message.partition(separator)
        if found:
            return head, found, body
    return message, "", ""


def _mask_header(name: str, value: str) -> str:
    """Cookie names stay (they say which session it was); every value goes."""
    if name.lower() in ("cookie", "set-cookie"):
        first, *attributes = value.split(";") if name.lower() == "set-cookie" else (value,)
        pairs = first.split(";") if name.lower() == "cookie" else [first]
        masked = "; ".join(
            f"{p.split('=', 1)[0].strip()}={MASK}" if "=" in p else MASK for p in pairs if p.strip()
        )
        tail = "".join(f";{a}" for a in attributes)  # Path, HttpOnly...: not secret
        return f" {masked}{tail}"
    scheme = value.strip().split(" ", 1)
    if name.lower() in ("authorization", "proxy-authorization") and len(scheme) == 2:
        return f" {scheme[0]} {MASK}"
    return f" {MASK}"


def nuclei_jsonl(output: str) -> str:
    """nuclei's JSON lines with each match's exchange masked and its response cut."""
    lines = []
    for line in output.splitlines():
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            lines.append(text(line))  # not a match: still no secrets
            continue
        if isinstance(hit, dict):
            masked = _hit(hit)
            # Nothing to mask: the line stays byte for byte what nuclei wrote.
            lines.append(line if masked == hit else json.dumps(masked, ensure_ascii=False))
        else:
            lines.append(text(line))
    return "\n".join(lines) + ("\n" if output.endswith("\n") else "")


def _hit(hit: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in hit.items():
        if key == "request" and isinstance(value, str):
            out[key] = http(value)
        elif key == "response" and isinstance(value, str):
            out[key] = http(value, body_limit=MAX_BODY)
        else:
            out[key] = _value(value)
    return out


def _value(value: Any) -> Any:
    if isinstance(value, str):
        return text(value)
    if isinstance(value, list):
        return [_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _value(v) for k, v in value.items()}
    return value
