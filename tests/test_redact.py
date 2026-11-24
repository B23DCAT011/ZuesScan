"""Masking the target's secrets in evidence before it is stored (G24)."""

from __future__ import annotations

import json

import pytest

from zues_scan import redact
from zues_scan.redact import MASK

SHADOW = "root:$6$rOUNDsalt$Q8zjk1Z9jvzS0cSbG5u0Hk1bW2:19000:0:99999:7:::"


def test_credentials_in_headers_are_masked_but_the_exchange_stays_readable() -> None:
    request = (
        "GET /admin HTTP/1.1\r\nHost: shop.example\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n"
        "Cookie: lang=vi; PHPSESSID=8f2c1e\r\nX-Requested-With: XMLHttpRequest\r\n\r\n"
    )

    masked = redact.http(request)

    assert masked.startswith("GET /admin HTTP/1.1\r\nHost: shop.example\r\n")
    assert f"Authorization: Basic {MASK}\r\n" in masked
    assert f"Cookie: lang={MASK}; PHPSESSID={MASK}\r\n" in masked  # which cookies: kept
    assert "X-Requested-With: XMLHttpRequest\r\n" in masked
    assert "YWRtaW46" not in masked and "8f2c1e" not in masked


def test_set_cookie_keeps_its_attributes() -> None:
    response = "HTTP/1.1 302 Found\nSet-Cookie: sid=s3cr3t-value; Path=/; HttpOnly\n\n"
    assert f"Set-Cookie: sid={MASK}; Path=/; HttpOnly" in redact.http(response)


@pytest.mark.parametrize(
    "header", ["X-Api-Key", "X-Auth-Token", "X-Vault-Token", "X-Session-Id", "Api-Key", "X-Secret"]
)
def test_headers_named_after_secrets(header: str) -> None:
    assert redact.http(f"GET / HTTP/1.1\n{header}: abc123xyz\n\n").count(MASK) == 1


def test_a_long_body_is_cut_and_says_so() -> None:
    response = "HTTP/1.1 200 OK\n\n" + "A" * 5000

    masked = redact.http(response, body_limit=redact.MAX_BODY)

    assert masked.count("A") == redact.MAX_BODY
    assert masked.endswith(f"[... {5000 - redact.MAX_BODY} more characters not kept: G24]")


@pytest.mark.parametrize(
    ("given", "gone"),
    [
        (SHADOW, "rOUNDsalt"),
        ("DB_PASSWORD=hunter2", "hunter2"),
        ('{"api_key": "sk_live_51HxYz"}', "sk_live_51HxYz"),
        ("client_secret: 9f8e7d6c", "9f8e7d6c"),
        ("/login?user=bob&pwd=letmein&next=/", "letmein"),
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r", "dBjftJeZ"),
        ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("ftp://anon:p4ss@files.example/pub", "p4ss"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
            "-----END OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXk",
        ),
    ],
)
def test_secrets_in_text(given: str, gone: str) -> None:
    masked = redact.text(given)
    assert gone not in masked and MASK in masked


def test_ordinary_text_is_left_alone() -> None:
    text = "root:x:0:0:root:/root:/bin/bash\nApache/2.4.49 (Unix) — Welcome to nginx!"
    assert redact.text(text) == text  # /etc/passwd has no secret: it proves the traversal


def test_nuclei_output_is_masked_match_by_match() -> None:
    hit = {
        "template-id": "CVE-2021-41773",
        "matched-at": "http://10.0.0.5/cgi-bin/.%2e/.%2e/etc/shadow?token=abcdef",
        "extracted-results": [SHADOW],
        "request": "GET /cgi-bin/.%2e/.%2e/etc/shadow HTTP/1.1\r\nCookie: sid=zz9\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\n\r\n" + SHADOW + "\n" + "x" * 4000,
        "info": {"severity": "critical", "classification": {"cvss-score": 9.8}},
    }
    output = json.dumps(hit) + "\n[INF] not a match\n"

    lines = redact.nuclei_jsonl(output).splitlines()

    masked = json.loads(lines[0])
    assert masked["template-id"] == "CVE-2021-41773" and masked["info"] == hit["info"]
    assert "rOUNDsalt" not in lines[0] and "zz9" not in lines[0] and "abcdef" not in lines[0]
    assert len(masked["response"]) < redact.MAX_BODY + 200
    assert lines[1] == "[INF] not a match"


def test_a_match_with_nothing_to_mask_is_kept_byte_for_byte() -> None:
    line = '{"template-id":"CVE-2023-48795","host":"10.0.0.5:22","matched-at":"10.0.0.5:22"}'
    assert redact.nuclei_jsonl(line + "\n") == line + "\n"
