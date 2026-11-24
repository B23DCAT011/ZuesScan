"""Which third-party plugins a service loads (G25): pinned by package, version and the
SHA-256 of their installed files, checked before anything of them is imported; and the
activity their operator granted, not the one they claim."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest

from zues_scan import cli, doctor
from zues_scan.plugins import registry
from zues_scan.plugins.registry import PinError, PluginContext, PluginError, Policy
from zues_scan.scanning import ScanSpec, execute
from zues_scan.scope import Activity, Scope, ScopeError
from zues_scan.server.config import ConfigError, from_environment, load_config
from zues_scan.server.jobs import spec_for

MODULE = "zues_probe"

SOURCE = """
from zues_scan.plugins.base import ScanResult
from zues_scan.plugins.registry import PluginSpec
from zues_scan.scope import Activity


class Probe:
    name = "probe"
    activity = Activity.{activity}

    def is_available(self):
        return True

    def version(self):
        return "1.0.0"

    def check(self, plan, assets):
        return ScanResult()


PLUGIN = PluginSpec("probe", "check", Probe.activity, "a test package", lambda ctx: Probe())
"""


class Site:
    """A folder on sys.path holding one installed package, `zues-probe`, as pip lays out a
    wheel: its module, its .dist-info and the RECORD that lists both."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.info = root / "zues_probe-1.0.0.dist-info"

    def install(
        self,
        activity: str = "SCAN",
        entry: str = "zues_probe:PLUGIN",
        record: bool = True,
        editable: bool = False,
        source: str | None = None,
    ) -> None:
        package = self.root / MODULE
        package.mkdir(exist_ok=True)
        code = source if source is not None else SOURCE.format(activity=activity)
        (package / "__init__.py").write_text(code, encoding="utf-8")
        self.info.mkdir(exist_ok=True)
        files = {
            "METADATA": "Metadata-Version: 2.1\nName: zues-probe\nVersion: 1.0.0\n",
            "entry_points.txt": f"[zues_scan.plugins]\nprobe = {entry}\n",
            "INSTALLER": "pip\n",
        }
        if editable:
            files["direct_url.json"] = json.dumps(
                {"url": "file:///src/zues-probe", "dir_info": {"editable": True}}
            )
        for name, text in files.items():
            (self.info / name).write_text(text, encoding="utf-8")
        listed = [f"{MODULE}/__init__.py", *(f"{self.info.name}/{n}" for n in files)]
        listed += [f"{self.info.name}/RECORD", f"{MODULE}/__pycache__/__init__.cpython-313.pyc"]
        listed.append("../../bin/zues-probe")  # a script the installer generated
        if record:
            text = "".join(f"{path},,\n" for path in listed)
            (self.info / "RECORD").write_text(text, encoding="utf-8")

    def entries(self) -> list[Any]:
        return list(metadata.PathDistribution(self.info).entry_points)


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Site]:
    root = tmp_path / "site-packages"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    sys.modules.pop(MODULE, None)
    installed = Site(root)
    installed.install()
    yield installed
    sys.modules.pop(MODULE, None)


def pinned(site: Site, activity: str = "active") -> Policy:
    pin = registry.pin_for("probe", site.entries)
    return Policy(
        (registry.make_pin("probe", activity, pin.package, pin.version, pin.sha256, "t"),)
    )


# --- loading --------------------------------------------------------------------------------


def test_a_service_loads_no_package_it_does_not_pin_and_never_imports_one(site: Site) -> None:
    loaded = registry.load(site.entries, Policy())

    assert "probe" not in loaded.plugins
    assert "not allowed" in loaded.left_out["probe"] and "zues-probe" in loaded.left_out["probe"]
    assert loaded.problems == []  # the policy working is not a problem
    assert MODULE not in sys.modules  # its code never ran
    with pytest.raises(PluginError, match="plugin probe is not loaded: installed"):
        loaded.get("probe", "check")


def test_without_a_policy_every_installed_plugin_loads(site: Site) -> None:
    loaded = registry.load(site.entries)
    assert loaded.plugins["probe"].source == "zues-probe"
    assert loaded.plugins["probe"].activity is Activity.SCAN


def test_a_pinned_plugin_loads_with_the_activity_its_operator_granted(site: Site) -> None:
    loaded = registry.load(site.entries, pinned(site))  # --pin's default: active

    spec = loaded.get("probe", "check")
    assert (spec.activity, spec.source) == (Activity.ACTIVE, "zues-probe")
    assert loaded.declared == {"probe": Activity.SCAN}  # its own claim, kept for the record
    [plugin] = loaded.build(["probe"], "check", PluginContext())
    assert plugin.activity is Activity.ACTIVE and plugin.name == "probe"
    assert plugin.version() == "1.0.0"  # everything else is the plugin's
    # The scope gate reads the granted activity: it claims scan, a scan-only scope refuses it.
    with pytest.raises(ScopeError, match="probe \\(active\\) goes beyond"):
        Scope.from_text("10.0.0.0/24\n", "t").check_activity([(plugin.name, plugin.activity)])

    exact = registry.load(site.entries, pinned(site, "scan"))
    assert exact.get("probe", "check").activity is Activity.SCAN and exact.declared == {}
    [plugin] = exact.build(["probe"], "check", PluginContext())
    assert type(plugin).__name__ == "ProcessPlugin"  # nothing to wrap: it runs in a child


def test_a_plugin_that_claims_more_than_it_was_granted_is_left_out(site: Site) -> None:
    site.install(activity="ACTIVE")
    loaded = registry.load(site.entries, pinned(site, "scan"))
    assert "probe" not in loaded.plugins
    assert "declares active" in loaded.left_out["probe"]
    assert "raise the pin's activity" in loaded.problems[0]


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        (
            lambda s: (s.root / MODULE / "__init__.py").write_text("import os\n", encoding="utf-8"),
            "differ from the pinned ones",
        ),
        (
            lambda s: (s.info / "entry_points.txt").write_text(
                "[zues_scan.plugins]\nprobe = zues_probe:OTHER\n", encoding="utf-8"
            ),
            "differ from the pinned ones",  # what loads is part of the pin too
        ),
        (lambda s: (s.root / MODULE / "__init__.py").unlink(), "missing or unreadable"),
    ],
)
def test_a_changed_package_is_refused_before_it_runs(
    site: Site, tamper: Callable[[Site], Any], reason: str
) -> None:
    policy = pinned(site)
    tamper(site)
    loaded = registry.load(site.entries, policy)

    assert "probe" not in loaded.plugins and reason in loaded.left_out["probe"]
    assert reason in loaded.problems[0]  # unlike "not allowed", this is someone's doing
    assert MODULE not in sys.modules


def test_the_pin_ignores_what_differs_between_two_installs(site: Site) -> None:
    before = registry.pin_for("probe", site.entries).sha256
    (site.info / "INSTALLER").write_text("uv\n", encoding="utf-8")
    (site.root / MODULE / "__pycache__").mkdir()
    (site.root / MODULE / "__pycache__" / "__init__.cpython-313.pyc").write_bytes(b"\x00junk")
    assert registry.pin_for("probe", site.entries).sha256 == before


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"version": "0.9.0"}, "1.0.0 is installed, the pin says 0.9.0"),
        ({"package": "zues-other"}, "comes from the package zues-probe, the pin says zues-other"),
    ],
)
def test_a_pin_names_one_release_of_one_package(
    site: Site, change: dict[str, str], reason: str
) -> None:
    pin = registry.pin_for("probe", site.entries)
    fields = {"package": pin.package, "version": pin.version, **change}
    other = registry.make_pin(
        "probe", "active", fields["package"], fields["version"], pin.sha256, "t"
    )
    loaded = registry.load(site.entries, Policy((other,)))
    assert reason in loaded.left_out["probe"]


def test_an_entry_point_into_another_package_is_refused(site: Site) -> None:
    site.install(entry="json:PLUGIN")  # names a module zues-probe does not install
    reason = "names the module 'json', which zues-probe does not install"
    with pytest.raises(PinError, match=reason):
        registry.pin_for("probe", site.entries)  # --pin will not print it
    digest = registry.package_digest(metadata.PathDistribution(site.info))
    pin = registry.make_pin("probe", "active", "zues-probe", "1.0.0", digest, "t")
    loaded = registry.load(site.entries, Policy((pin,)))  # nor load it, pinned by hand
    assert reason in loaded.left_out["probe"]


def test_editable_or_recordless_installs_cannot_be_pinned(site: Site) -> None:
    site.install(editable=True)
    with pytest.raises(PinError, match="editable install"):
        registry.pin_for("probe", site.entries)
    (site.info / "direct_url.json").unlink()
    (site.info / "RECORD").unlink()
    with pytest.raises(PinError, match="not installed from a wheel"):
        registry.pin_for("probe", site.entries)


def test_pin_for_names_only_installed_third_party_plugins(site: Site) -> None:
    with pytest.raises(PluginError, match="nmap is built in"):
        registry.pin_for("nmap", site.entries)
    with pytest.raises(PluginError, match="no installed package provides a plugin named 'x'"):
        registry.pin_for("x", site.entries)


def test_a_pin_for_a_package_that_is_not_installed_is_reported(site: Site) -> None:
    pin = registry.make_pin("ghost", "scan", "zues-ghost", "2.0", "a" * 64, "t")
    loaded = registry.load(site.entries, Policy((pin,), "service.toml"))
    assert loaded.problems == [
        "plugin ghost is allowed in service.toml but no installed package provides it "
        "(pip install zues-ghost==2.0)"
    ]


# --- writing pins down ----------------------------------------------------------------------


def test_pins_as_text_and_as_toml(site: Site) -> None:
    pin = registry.pin_for("probe", site.entries)
    assert pin.activity is Activity.ACTIVE and (pin.package, pin.version) == ("zues-probe", "1.0.0")
    assert registry.pins_from_text(f"{pin.line()}, ") == (pin,)
    assert registry.pins_from_text("none") == () == registry.pins_from_text(" ")
    assert pin.toml().startswith("[[plugins]]\n") and f'sha256 = "{pin.sha256}"' in pin.toml()


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("probe:active:zues-probe:" + "a" * 64, "write name:activity:package==version:sha256"),
        ("probe:exploit:zues-probe==1.0:" + "a" * 64, "unknown activity 'exploit'"),
        ("probe:scan:zues-probe==1.0:abc", "64 lowercase hex digits"),
        ("nmap:scan:zues-nmap==1.0:" + "a" * 64, "nmap is built in"),
        ("Probe:scan:zues-probe==1.0:" + "a" * 64, "lowercase letters, digits and -"),
        ("probe:scan:zues-probe==1 0:" + "a" * 64, "write name:activity"),
        ("probe:scan:zues probe==1.0:" + "a" * 64, "write name:activity"),
        (
            f"probe:scan:a==1:{'a' * 64},probe:scan:b==1:{'b' * 64}",
            "two pins for the plugin 'probe'",
        ),
    ],
)
def test_bad_pins_are_refused(text: str, error: str) -> None:
    with pytest.raises(PluginError, match=error):
        registry.pins_from_text(text)


def _service(tmp_path: Path, plugins: str) -> Path:
    path = tmp_path / "service.toml"
    path.write_text(f'[service]\ndb = "x.db"\n{plugins}', encoding="utf-8")
    return path


def test_the_service_reads_its_pins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pin = registry.make_pin("probe", "scan", "zues-probe", "1.0.0", "c" * 64, "t")
    config = load_config(_service(tmp_path, pin.toml()))
    assert config.plugins.pins == (pin,) and "[[plugins]]" in config.plugins.where
    assert load_config(_service(tmp_path, "")).plugins == Policy(where=config.plugins.where)

    monkeypatch.setattr("zues_scan.server.managed.load_managed", lambda db: None, raising=False)
    monkeypatch.setenv("ZUES_DB", str(tmp_path / "env.db"))
    monkeypatch.setenv("ZUES_PLUGINS", pin.line())
    assert from_environment().plugins == Policy((pin,), "ZUES_PLUGINS")
    monkeypatch.setenv("ZUES_PLUGINS", "")  # compose passes it, set or not
    assert from_environment().plugins.pins == ()
    monkeypatch.setenv("ZUES_PLUGINS", "probe")
    with pytest.raises(ConfigError, match="ZUES_PLUGINS item 1"):
        from_environment()


@pytest.mark.parametrize(
    ("table", "error"),
    [
        ('[[plugins]]\nname = "probe"\n', "needs package, version, sha256, activity"),
        ('[[plugins]]\nname = "probe"\nsource = "x"\n', "unknown setting\\(s\\) source"),
        ('plugins = "probe"\n', "write each plugin as a \\[\\[plugins\\]\\] table"),
    ],
)
def test_bad_plugin_tables_stop_the_service(tmp_path: Path, table: str, error: str) -> None:
    text = table if table.startswith("[[") else table
    path = tmp_path / "service.toml"
    body = f'{text}[service]\ndb = "x.db"\n' if not text.startswith("[[") else None
    path.write_text(body or f'[service]\ndb = "x.db"\n{text}', encoding="utf-8")
    with pytest.raises(ConfigError, match=error):
        load_config(path)


def test_a_service_job_scans_with_the_services_pins(tmp_path: Path) -> None:
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    pin = registry.make_pin("probe", "scan", "zues-probe", "1.0.0", "c" * 64, "t")
    path = _service(
        tmp_path,
        f'[[targets]]\nname = "web"\ntarget = "10.0.0.5"\nscope = "'
        f'{tmp_path.as_posix()}/scope.txt"\nchecks = ["probe"]\n{pin.toml()}',
    )
    config = load_config(path)
    assert spec_for(config, config.target("web"), "alice").plugins == config.plugins


# --- the command line -----------------------------------------------------------------------


def test_zues_plugins_pin_prints_what_to_paste(
    site: Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(registry, "_entry_points", site.entries)
    monkeypatch.delenv("ZUES_PLUGINS", raising=False)
    monkeypatch.delenv("ZUES_CONFIG", raising=False)
    monkeypatch.delenv("ZUES_DB", raising=False)

    assert cli.main(["plugins", "--pin", "probe"]) == 0
    out = capsys.readouterr().out
    pin = registry.pin_for("probe", site.entries)
    assert pin.toml() in out and f"ZUES_PLUGINS={pin.line()}" in out
    assert "Review its code" in out and MODULE not in sys.modules
    assert cli.main(["plugins", "--pin", "nope"]) == 2
    assert "no installed package provides" in capsys.readouterr().err

    assert cli.main(["plugins"]) == 0  # this command line on its own: every plugin loads
    assert "A service loads only those pinned" in capsys.readouterr().out
    monkeypatch.setenv("ZUES_PLUGINS", "none")
    assert cli.main(["plugins"]) == 0
    assert "not loaded: probe: installed (from zues-probe) but not allowed in ZUES_PLUGINS" in (
        capsys.readouterr().out
    )
    monkeypatch.setenv("ZUES_PLUGINS", pin.line())
    assert cli.main(["plugins", "--json"]) == 0
    [row] = [r for r in json.loads(capsys.readouterr().out)["plugins"] if r["name"] == "probe"]
    assert (row["activity"], row["declared"]) == ("active", "scan")


def test_zues_plugins_shows_what_a_service_loads(
    site: Site, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(registry, "_entry_points", site.entries)
    path = _service(tmp_path, "")
    assert cli.main(["plugins", "--config", str(path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "probe" not in {r["name"] for r in data["plugins"]}
    assert [r["name"] for r in data["left_out"]] == ["probe"]


def test_a_scan_with_a_bad_zues_plugins_stops_before_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    monkeypatch.setenv("ZUES_PLUGINS", "probe")
    outcome = execute(ScanSpec("10.0.0.5", str(tmp_path / "scope.txt"), db=str(tmp_path / "x.db")))
    assert outcome.code == 2 and "ZUES_PLUGINS item 1" in outcome.messages[0]
    assert not (tmp_path / "x.db").exists()


def test_doctor_reports_a_changed_plugin(site: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_entry_points", site.entries)
    policy = pinned(site)
    states = {c.name: c.status for c in doctor.check_plugins(policy)}
    assert states["plugin probe"] == doctor.OK
    (site.root / MODULE / "__init__.py").write_text("import os\n", encoding="utf-8")
    [check] = doctor.check_plugins(policy)
    assert check.status == doctor.ERROR and "differ from the pinned ones" in check.detail
    [check] = doctor.check_plugins(Policy())
    assert check.status == doctor.INFO and "not loaded: installed" in check.detail
