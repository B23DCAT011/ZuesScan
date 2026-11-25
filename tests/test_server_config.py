"""The service configuration: only what service.toml lists can be scanned, checked early."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from zues_scan.server.config import ConfigError, load_config, parse_every

DIGEST = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # sha256("test")


def write_config(tmp_path: Path, body: str) -> Path:
    """service.toml in `tmp_path`, with a scope file ready for its targets."""
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    path = tmp_path / "service.toml"
    body = body.replace("{dir}", tmp_path.as_posix())
    body = body.replace("{digest}", DIGEST).replace("{DIGEST}", DIGEST.upper())
    path.write_text(body, encoding="utf-8")
    return path


FULL = """
[service]
db = "{dir}/zues.db"
cve_cache = "{dir}/cve.db"
redis_url = "redis://redis:6379/1"
queue = "scans"

[[tokens]]
name = "alice"
sha256 = "{digest}"
role = "operator"

[[tokens]]
name = "bob"
sha256 = "{DIGEST}"

[[targets]]
name = "office-lan"
target = "10.0.0.0/24"
scope = "{dir}/scope.txt"
profile = "full"
every = "24h"
engagement = "PT-2026-014"
nuclei = true

[[targets]]
name = "web"
target = "10.0.0.5"
scope = "{dir}/scope.txt"

[notify]
webhook = "https://hooks.example.com/abc"
min_priority = "P1"
"""


def test_a_full_config_is_read(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, FULL))

    assert config.db == f"{tmp_path.as_posix()}/zues.db"
    assert config.cve_cache == f"{tmp_path.as_posix()}/cve.db"
    assert (config.redis_url, config.queue) == ("redis://redis:6379/1", "scans")
    assert [(t.name, t.role) for t in config.tokens] == [("alice", "operator"), ("bob", "viewer")]
    assert config.tokens[1].sha256 == DIGEST  # stored lowercase, however it was written
    office = config.target("office-lan")
    assert office.target == "10.0.0.0/24"
    assert office.profile == "full"
    assert office.every == timedelta(hours=24)
    assert office.engagement == "PT-2026-014"
    assert office.nuclei is True
    web = config.target("web")
    assert (web.profile, web.every, web.nuclei) == ("standard", None, False)
    assert config.notify.webhook == "https://hooks.example.com/abc"
    assert config.notify.min_priority == "P1"


def test_the_minimal_config_has_safe_defaults(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, '[service]\ndb = "x.db"\n'))

    assert config.redis_url == "redis://localhost:6379/0"
    assert config.queue == "zues"
    assert config.tokens == () and config.targets == {}
    assert config.notify.webhook is None and config.notify.min_priority == "P2"


def test_only_configured_targets_can_be_named(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, FULL))

    with pytest.raises(ConfigError, match="no target named '10.0.0.9'"):
        config.target("10.0.0.9")


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ("[service]\n", r"needs db"),
        ('[service]\ndb = "x"\nport = 1\n', r"\[service\]: unknown key\(s\) port"),
        ('[service]\ndb = "x"\n[extra]\n', r"unknown key\(s\) extra"),
        (
            '[service]\ndb = "x"\n[[tokens]]\nname = "a"\ntoken = "s3cret"\nsha256 = "{digest}"\n',
            r"store the token's sha256, never the token",
        ),
        ('[service]\ndb = "x"\n[[tokens]]\nname = "a"\nsha256 = "abc"\n', r"64 hex"),
        ('[service]\ndb = "x"\n[[tokens]]\nname = "a"\n', r"missing 'sha256'"),
        (
            '[service]\ndb = "x"\n[[tokens]]\nname = "a"\nsha256 = "{digest}"\nrole = "root"\n',
            r"role must be one of viewer, operator",
        ),
        (
            '[service]\ndb = "x"\n'
            + '[[tokens]]\nname = "a"\nsha256 = "{digest}"\n'
            + '[[tokens]]\nname = "a"\nsha256 = "{digest}"\n',
            r"two tokens have the same name",
        ),
        ('[service]\ndb = "x"\n[[targets]]\nname = "a"\ntarget = "10.0.0.1"\n', r"missing"),
        (
            '[service]\ndb = "x"\n[[targets]]\nname = "Office LAN"\ntarget = "10.0.0.1"\n'
            'scope = "{dir}/scope.txt"\n',
            r"lowercase letters",
        ),
        (
            '[service]\ndb = "x"\n[[targets]]\nname = "a"\ntarget = "10.0.0.1"\n'
            'scope = "{dir}/nope.txt"\n',
            r"scope file not found",
        ),
        (
            '[service]\ndb = "x"\n[[targets]]\nname = "a"\ntarget = "10.0.0.1"\n'
            'scope = "{dir}/scope.txt"\nports = "1-65535"\n',
            r"unknown key\(s\) ports",
        ),
        (
            '[service]\ndb = "x"\n'
            + '[[targets]]\nname = "a"\ntarget = "10.0.0.1"\nscope = "{dir}/scope.txt"\n' * 2,
            r"two targets are named 'a'",
        ),
        ('[service]\ndb = "x"\n[notify]\nmin_priority = "high"\n', r"P1, P2, P3 or P4"),
        ('[service]\ndb = "x"\n[notify]\nwebhook = "file:///etc/passwd"\n', r"http\(s\) URL"),
        ('[service]\ndb = "x"\n[notify]\nemail = "a@b"\n', r"unknown key\(s\) email"),
        ('[service]\ndb = "x"\n[notify]\nsecret = "short"\n', r"secret must be at least 16"),
        (
            f'[service]\ndb = "x"\n[[tokens]]\nname = "a"\nsha256 = "{"0" * 64}"\n'
            'expires = "soon"\n',
            r"expires must be a date",
        ),
        ('[service]\ndb = "x"\n[notify]\nfailed_scans = 0\n', r"failed_scans must be a whole"),
        ('[service]\ndb = "x"\n[notify]\nfailed_scans = true\n', r"failed_scans must be a"),
        ('[service]\ndb = "x"\n[notify]\nkeep_days = 6\n', r"keep_days must be .* from 7 to 3650"),
        (
            '[service]\ndb = "x"\n[notify]\nprevious_secret = "0123456789abcdef-old"\n',
            r"previous_secret is the secret being replaced: set the new one in \[notify\] secret",
        ),
        (
            '[service]\ndb = "x"\n[notify]\nsecret = "0123456789abcdef-new"\n'
            'previous_secret = "0123456789abcdef-new"\n',
            r"previous_secret is the same as the secret",
        ),
        (
            '[service]\ndb = "x"\n[notify]\nsecret = "0123456789abcdef-new"\n'
            'previous_secret = "short"\n',
            r"previous_secret must be at least 16",
        ),
        ('[service]\ndb = "x"\n[notify]\nkeep_days = 3651\n', r"keep_days must be"),
        ('[service]\ndb = "x"\n[notify]\nkeep_days = true\n', r"keep_days must be"),
        ("[service\n", r"cannot read service config"),
    ],
)
def test_an_invalid_config_stops_the_service(tmp_path: Path, body: str, error: str) -> None:
    with pytest.raises(ConfigError, match=error):
        load_config(write_config(tmp_path, body))


def test_a_missing_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="service config not found"):
        load_config(tmp_path / "service.toml")


@pytest.mark.parametrize(
    ("text", "delta"),
    [("5m", timedelta(minutes=5)), ("6h", timedelta(hours=6)), (" 1D ", timedelta(days=1))],
)
def test_every_reads_minutes_hours_and_days(text: str, delta: timedelta) -> None:
    assert parse_every(text) == delta


@pytest.mark.parametrize(("text", "error"), [("1w", "write it like"), ("4m", "at least 5")])
def test_every_rejects_other_units_and_too_short_intervals(text: str, error: str) -> None:
    with pytest.raises(ConfigError, match=error):
        parse_every(text)
