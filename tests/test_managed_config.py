"""Scopes, targets and tokens edited in the dashboard: kept, checked, audited, merged."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import lab_resolver

from zues_scan.cli import main
from zues_scan.scope import Scope
from zues_scan.server import managed
from zues_scan.server.config import DASHBOARD, FILE, ServiceConfig, load_config
from zues_scan.server.jobs import spec_for
from zues_scan.storage import Storage

SCOPE = "@engagement PT-9\n10.0.0.0/24\nscanme.lab\n*.scanme.lab\n!10.0.0.9\n"
ACTIVE = "@activity active\n10.0.0.0/24\n"


@pytest.fixture
def service(tmp_path: Path) -> Path:
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    config = tmp_path / "service.toml"
    config.write_text(
        f'[service]\ndb = "{tmp_path.as_posix()}/zues.db"\n\n'
        f'[[targets]]\nname = "office"\ntarget = "10.0.0.0/24"\n'
        f'scope = "{tmp_path.as_posix()}/scope.txt"\n',
        encoding="utf-8",
    )
    return config


def fresh(service: Path) -> tuple[Storage, ServiceConfig]:
    config = load_config(service)
    return Storage(config.db), config


def test_a_scope_from_text_is_the_scope_from_its_file(tmp_path: Path) -> None:
    path = tmp_path / "s.txt"
    path.write_bytes(SCOPE.encode("utf-8"))  # as is: no newline translation on Windows
    from_file, from_text = Scope.from_file(path), Scope.from_text(SCOPE, "dashboard scope lab")
    assert (from_file.sha256, from_file.text) == (from_text.sha256, from_text.text)
    assert from_text.path == "dashboard scope lab"
    with pytest.raises(Exception, match=r"scope x:2: "):
        Scope.from_text("10.0.0.0/24\nnot a host!\n", "scope x")


def test_saved_scopes_and_targets_join_the_file_config(
    service: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(managed, "_found", lambda binary: True)  # nmap here or not
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        config = load_config(service)
        saved = managed.save_target(
            store,
            config,
            "web",
            {"target": "10.0.0.20", "scope": "lab", "profile": "quick", "every": "6h"},
            "alice",
            resolver=lab_resolver,
        )
        assert saved.warnings == []
        version = store.managed_version()
    config = load_config(service)
    assert config.managed_version == version == 2
    office, web = config.targets["office"], config.targets["web"]
    assert (office.source, office.scope_text) == (FILE, None)
    assert (web.source, web.scope, web.scope_text, web.profile) == (
        DASHBOARD,
        "lab",
        SCOPE,
        "quick",
    )
    spec = spec_for(config, web, "alice")
    assert (spec.scope, spec.scope_text) == ("dashboard scope lab", SCOPE)


def test_every_change_is_in_the_audit_chain_and_the_chain_holds(service: Path) -> None:
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        token = managed.create_token(store, load_config(service), "carol", "operator", "alice")
        managed.delete_token(store, load_config(service), "carol", "alice")
        events = store.audit_events()
        report = store.verify_audit()
        stored = [dict(r) for r in store.managed_tokens()]
    kinds = [(e.kind, e.target, e.detail["action"]) for _, e, _ in events]
    assert kinds == [
        ("config", "scope:lab", "scope saved"),
        ("config", "token:carol", "token created"),
        ("config", "token:carol", "token deleted"),
    ]
    assert report.intact and report.events == 3
    assert token not in json.dumps([e.detail for _, e, _ in events])  # never the token
    assert stored == []


def test_service_toml_wins_a_name_and_broken_entries_are_reported(service: Path) -> None:
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        config = load_config(service)
        managed.save_target(store, config, "web", {"target": "10.0.0.5", "scope": "lab"}, "a")
        # Written behind the checks' back: a name service.toml has, a scope that is gone.
        store.save_managed_target("office", {"target": "10.0.0.1", "scope": "lab"}, "x")
        store.save_managed_target("ghost", {"target": "10.0.0.1", "scope": "nope"}, "x")
    config = load_config(service)
    assert config.targets["office"].source == FILE
    assert "web" in config.targets and "ghost" not in config.targets
    assert any("'office' left out: service.toml defines" in p for p in config.problems)
    assert any("'ghost' left out" in p and "no scope named 'nope'" in p for p in config.problems)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"target": "10.0.0.5", "scope": "nope"}, "no scope named 'nope'"),
        ({"target": "192.168.1.1", "scope": "lab"}, "outside the authorised scope"),
        ({"target": "10.0.0.5", "scope": "lab", "checks": ["nuclei"]}, "@activity active"),
        ({"target": "10.0.0.5", "scope": "lab", "checks": ["nmap"]}, "nmap is a scanner"),
        ({"target": "10.0.0.5", "scope": "lab", "scanners": ["nessus"]}, "unknown scanner"),
        ({"target": "10.0.0.5", "scope": "lab", "profile": "turbo"}, "profile 'turbo'"),
        ({"target": "10.0.0.5", "scope": "lab", "every": "1m"}, "at least 5 minutes"),
        ({"target": "corp.example", "scope": "lab", "discover": True}, "needs '\\*.corp.example'"),
        ({"target": "", "scope": "lab"}, "missing 'target'"),
    ],
)
def test_a_target_is_refused_before_it_is_saved(
    service: Path, body: dict[str, object], message: str
) -> None:
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        config = load_config(service)
        with pytest.raises(managed.ManagedError, match=message):
            managed.save_target(store, config, "web", body, "alice", resolver=lab_resolver)
        assert store.managed_targets() == []


def test_what_only_a_scan_can_tell_is_a_warning(service: Path) -> None:
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        managed.save_scope(store, config, "deep", ACTIVE, "alice")
        config = load_config(service)

        def nothing(name: str) -> list[str]:
            from zues_scan.scope import ResolutionError

            raise ResolutionError(f"{name} does not resolve")

        named = {"target": "new.scanme.lab", "scope": "lab"}
        saved = managed.save_target(store, config, "named", named, "a", resolver=nothing)
        assert any("does not resolve now" in w for w in saved.warnings)
        nuclei = managed.save_target(
            store,
            config,
            "deep",
            {"target": "10.0.0.5", "scope": "deep", "checks": ["nuclei"]},
            "a",
        )
        assert nuclei.name == "deep"  # @activity active allows it


def test_service_toml_targets_are_read_only_here(service: Path) -> None:
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        config = load_config(service)
        with pytest.raises(managed.ManagedError, match="defined in service.toml"):
            managed.save_target(
                store, config, "office", {"target": "10.0.0.5", "scope": "lab"}, "a"
            )
        with pytest.raises(managed.ManagedError, match="defined in service.toml"):
            managed.delete_target(store, config, "office", "a")


def test_scopes_are_checked_and_protected(service: Path) -> None:
    store, config = fresh(service)
    with store:
        with pytest.raises(managed.ManagedError, match=r"scope lab:2: "):
            managed.save_scope(store, config, "lab", "10.0.0.0/24\n@activity reckless\n", "a")
        with pytest.raises(managed.ManagedError, match="scope name"):
            managed.save_scope(store, config, "Lab Scope", SCOPE, "a")
        assert (
            "allows nothing"
            in managed.save_scope(store, config, "empty", "# none\n", "a").warnings[0]
        )
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        config = load_config(service)
        managed.save_target(store, config, "web", {"target": "10.0.0.20", "scope": "lab"}, "a")
        config = load_config(service)
        with pytest.raises(managed.ManagedError, match="used by web"):
            managed.delete_scope(store, config, "lab", "a")
        # Narrowing a scope under a target is allowed, but said.
        narrowed = managed.save_scope(store, config, "lab", "10.0.0.0/28\n", "alice")
        assert any(w.startswith("target web:") for w in narrowed.warnings)


def test_tokens_keep_only_their_hash_and_an_admin_remains(service: Path) -> None:
    store, config = fresh(service)
    with store:
        token = managed.create_token(store, config, "root", "admin", "setup")
        (row,) = store.managed_tokens()
        assert row["sha256"] == hashlib.sha256(token.encode()).hexdigest()
        config = load_config(service)
        with pytest.raises(managed.ManagedError, match="exists already"):
            managed.create_token(store, config, "root", "viewer", "setup")
        with pytest.raises(managed.ManagedError, match="role must be one of"):
            managed.create_token(store, config, "eve", "god", "setup")
        with pytest.raises(managed.ManagedError, match="last admin"):
            managed.delete_token(store, config, "root", "setup")
    assert load_config(service).tokens[0].source == DASHBOARD


def test_zues_user_makes_the_first_admin(service: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["user", "--config", str(service), "add", "root", "--role", "admin"]) == 0
    token = capsys.readouterr().out.splitlines()[1]
    (made,) = load_config(service).tokens
    assert (made.name, made.role, made.sha256) == (
        "root",
        "admin",
        hashlib.sha256(token.encode()).hexdigest(),
    )
    assert main(["user", "--config", str(service), "list"]) == 0
    assert "root                     admin     dashboard" in capsys.readouterr().out
    assert main(["user", "--config", str(service), "remove", "root"]) == 2
    assert "last admin" in capsys.readouterr().err


def test_a_plugin_missing_on_the_server_is_a_warning(
    service: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(managed, "_found", lambda binary: binary != "httpx")
    store, config = fresh(service)
    with store:
        managed.save_scope(store, config, "lab", SCOPE, "alice")
        body = {"target": "10.0.0.5", "scope": "lab", "checks": ["httpx"]}
        saved = managed.save_target(store, load_config(service), "web", body, "alice")
    assert saved.warnings == [
        "not installed on this server: httpx (zues doctor; the scan will be partial until they are)"
    ]
