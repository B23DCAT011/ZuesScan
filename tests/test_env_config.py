"""A service without service.toml: settings from ZUES_* variables, the rest from the dashboard."""

from __future__ import annotations

from pathlib import Path

import pytest

from zues_scan.cli import main
from zues_scan.server import managed
from zues_scan.server.config import (
    ENVIRONMENT,
    ConfigError,
    config_path,
    from_environment,
    load_config,
)
from zues_scan.storage import Storage


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        "ZUES_CONFIG",
        "ZUES_REDIS_URL",
        "ZUES_QUEUE",
        "ZUES_CVE_CACHE",
        "ZUES_WEBHOOK",
        "ZUES_WEBHOOK_SECRET",
        "ZUES_NOTIFY_MIN_PRIORITY",
        "ZUES_NOTIFY_FAILED_SCANS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "zues.db"))


def test_which_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    assert config_path("given.toml") == "given.toml"
    assert config_path(None) == ENVIRONMENT
    monkeypatch.setenv("ZUES_CONFIG", "/config/service.toml")
    assert config_path(None) == "/config/service.toml"
    assert config_path("given.toml") == "given.toml"  # the flag wins


def test_settings_come_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ZUES_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("ZUES_QUEUE", "office")
    monkeypatch.setenv("ZUES_WEBHOOK", "https://hooks.example/x")
    config = load_config()
    assert (config.path, config.db, config.redis_url, config.queue) == (
        ENVIRONMENT,
        str(tmp_path / "zues.db"),
        "redis://redis:6379/0",
        "office",
    )
    assert config.notify.webhook == "https://hooks.example/x"
    assert config.targets == {} and config.tokens == ()
    monkeypatch.setenv("ZUES_WEBHOOK", "ftp://nope")
    with pytest.raises(ConfigError, match="ZUES_WEBHOOK"):
        from_environment()


def test_alert_settings_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # compose passes every variable, set or not: empty means "not set".
    for name in ("ZUES_WEBHOOK", "ZUES_WEBHOOK_SECRET", "ZUES_NOTIFY_FAILED_SCANS"):
        monkeypatch.setenv(name, "")
    notify = from_environment().notify
    assert (notify.webhook, notify.secret, notify.failed_scans) == (None, None, 3)

    monkeypatch.setenv("ZUES_WEBHOOK_SECRET", "0123456789abcdef-xyz")
    monkeypatch.setenv("ZUES_NOTIFY_FAILED_SCANS", "5")
    notify = from_environment().notify
    assert (notify.secret, notify.failed_scans) == ("0123456789abcdef-xyz", 5)
    monkeypatch.setenv("ZUES_WEBHOOK_SECRET", "short")
    with pytest.raises(ConfigError, match="ZUES_WEBHOOK_SECRET must be at least 16"):
        from_environment()
    monkeypatch.setenv("ZUES_WEBHOOK_SECRET", "0123456789abcdef-xyz")
    monkeypatch.setenv("ZUES_NOTIFY_FAILED_SCANS", "0")
    with pytest.raises(ConfigError, match="ZUES_NOTIFY_FAILED_SCANS must be a whole number"):
        from_environment()


def test_a_fresh_install_from_first_admin_to_a_target(capsys: pytest.CaptureFixture[str]) -> None:
    # What the README says to do after `docker compose up -d`: no file anywhere.
    assert main(["user", "add", "me", "--role", "admin"]) == 0
    capsys.readouterr()
    config = load_config()
    assert [(t.name, t.role) for t in config.tokens] == [("me", "admin")]
    with Storage(config.db) as store:
        managed.save_scope(store, config, "home", "10.0.0.0/24\n", "me")
        managed.save_target(
            store, load_config(), "nas", {"target": "10.0.0.5", "scope": "home"}, "me"
        )
    target = load_config().targets["nas"]
    assert (target.scope, target.scope_text) == ("home", "10.0.0.0/24\n")
