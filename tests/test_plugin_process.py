"""Plugins from other packages run in a process of their own (G25): a clean environment,
an empty working folder, no database or secrets, a time limit that stops the programs it
started too, a reply checked like any untrusted input — and their code never runs in
ZuesScan's own process."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePlugin, lab_asset, lab_resolver
from test_plugin_pins import MODULE, Site, pinned

from zues_scan.plugins import landlock, process, registry
from zues_scan.plugins.base import Attempt, ScanError, ScanResult
from zues_scan.plugins.registry import PluginContext, Policy
from zues_scan.plugins.wire import WireError, decode, encode
from zues_scan.profiles import ScanProfile
from zues_scan.scanning import ScanSpec, execute
from zues_scan.schema import (
    Asset,
    Confidence,
    Finding,
    Hop,
    RawOutput,
    ScanTarget,
    Service,
    Severity,
    WebPage,
)
from zues_scan.scope import Activity
from zues_scan.storage import Storage

# A check plugin whose behaviour each test picks through what it is asked to check: the
# plan's `requested` says what to do, its `hostname` carries an argument.
SOURCE = """
import json, os, subprocess, sys, time
from zues_scan.plugins.base import ScanError, ScanResult
from zues_scan.plugins.registry import PluginSpec
from zues_scan.schema import Asset, Finding, RawOutput, Severity, Confidence
from zues_scan.scope import Activity

LOADED_IN = os.getpid()


class Probe:
    name = "probe"
    activity = Activity.SCAN

    def is_available(self):
        return True

    def version(self):
        return f"1.0.0 pid {os.getpid()}"

    def check(self, plan, assets):
        what = plan.requested
        if what == "env":
            facts = {"env": sorted(os.environ), "cwd": os.getcwd(), "home": os.environ["HOME"],
                     "pid": os.getpid(), "loaded_in": LOADED_IN, "path": sys.path}
            return ScanResult(notes=[json.dumps(facts)])
        if what == "print":
            print("chatter on stdout")
            sys.stdout.write("{not json")
        if what == "crash":
            raise RuntimeError("boom")
        if what == "exit":
            sys.exit(3)
        if what == "scan-error":
            raw = RawOutput("probe", "text", ("probe",), "half an output")
            raise ScanError("the tool failed", plugin="probe", stderr="tool said no", output=raw)
        if what == "wrong-type":
            return {"assets": []}
        if what == "unsendable":
            return ScanResult(notes=[object()])
        if what == "sleep":
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
            print(f"grandchild {child.pid}", file=sys.stderr, flush=True)
            time.sleep(120)
        if what == "big":
            return ScanResult(notes=["x" * 100_000])
        if what == "files":
            secret, facts = plan.hostname, {}

            def attempt(name, action):
                try:
                    action()
                    facts[name] = "ok"
                except Exception as exc:
                    facts[name] = type(exc).__name__

            attempt("read the database", lambda: open(secret).read())
            attempt("write beside it", lambda: open(secret + ".new", "w").write("x"))
            attempt("write at home", lambda: open("scratch.txt", "w").write("x"))
            attempt("read os-release", lambda: open("/etc/os-release").read())
            attempt("read ZuesScan's environment",
                    lambda: open(f"/proc/{os.getppid()}/environ", "rb").read())
            attempt("cat the database",
                    lambda: subprocess.run(["cat", secret], check=True, capture_output=True))
            attempt("run a program", lambda: subprocess.run([sys.executable, "-c", "pass"],
                                                            check=True))
            return ScanResult(notes=[json.dumps(facts)])
        found = []
        for asset in assets:
            finding = Finding(asset=asset.host, ip=asset.ip, title="probe finding",
                              severity=Severity.HIGH, rule_id="probe",
                              confidence=Confidence.CONFIRMED, evidence="seen")
            found.append(Asset(host=asset.host, ip=asset.ip, findings=[finding]))
        raw = RawOutput("probe", "text", ("probe", *plan.addresses), "checked")
        return ScanResult(assets=found, raw=[raw])


PLUGIN = PluginSpec("probe", "check", Probe.activity, "a test package", lambda ctx: Probe())
"""

PLAN = ScanTarget("10.0.0.5", ("10.0.0.5",))


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Site]:
    """An installed package, `zues-probe` (see test_plugin_pins.Site)."""
    root = tmp_path / "site-packages"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    sys.modules.pop(MODULE, None)
    installed = Site(root)
    installed.install()
    yield installed
    sys.modules.pop(MODULE, None)


@pytest.fixture
def probe(site: Site) -> Site:
    site.install(source=SOURCE)
    return site


def built(site: Site, policy: Policy | None = None, **profile: Any) -> Any:
    loaded = registry.load(site.entries, policy)
    ctx = PluginContext(profile=ScanProfile("t", **profile))
    [plugin] = loaded.build(["probe"], "check", ctx)
    return plugin


def ask(plugin: Any, what: str, hostname: str | None = None) -> ScanResult:
    plan = ScanTarget(what, ("10.0.0.5",), hostname=hostname)
    result: ScanResult = plugin.check(plan, [Asset(host="10.0.0.5", ip="10.0.0.5")])
    return result


# --- what crosses the boundary ----------------------------------------------------------------


def test_the_schema_goes_across_and_back_unchanged() -> None:
    web = WebPage("http://10.0.0.5", 200, "Welcome", "nginx", ("nginx 1.20.0",))
    service = Service(22, name="ssh", product="OpenSSH", version="7.4", web=web)
    finding = Finding(
        asset="a.lab",
        title="t",
        severity=Severity.HIGH,
        service=service,
        cve="CVE-2018-15473",
        confidence=Confidence.FIRM,
        cwe=("CWE-200",),
        cvss_score=5.3,
        epss=0.5,
    )
    asset = Asset("a.lab", "10.0.0.5", [service], [finding], ["a.lab"], [Hop(1, "10.0.0.1", 0.4)])
    result = ScanResult(
        assets=[asset],
        raw=[RawOutput("p", "text", ("p", "-x"), "out", "err")],
        notes=["n"],
        cleared={"10.0.0.5": {"CVE-1", "CVE-2"}},
        tried=[Attempt("10.0.0.5", 80, "CVE-1", "template CVE-1 ran and did not match")],
        incomplete=True,
    )
    assert decode(ScanResult, json.loads(json.dumps(encode(result)))) == result
    target = ScanTarget("x", ("10.0.0.0/24",), ("10.0.0.1",), "x.lab", (("x.lab", "10.0.0.5"),))
    assert decode(ScanTarget, encode(target)) == target
    profile = ScanProfile("t", ports="22,80", timeout=60)
    assert decode(ScanProfile, encode(profile)) == profile


@pytest.mark.parametrize(
    ("data", "error"),
    [
        ({"assets": [], "evil": 1}, "unknown field\\(s\\) evil"),
        ({"assets": [{"ip": "10.0.0.5"}]}, "assets\\[0\\]: host is missing"),
        ({"assets": [{"host": "h", "services": [{"port": "22"}]}]}, "port: a whole number"),
        ({"assets": [{"host": "h", "services": [{"port": True}]}]}, "port: a whole number"),
        (
            {
                "assets": [
                    {"host": "h", "findings": [{"asset": "h", "title": "t", "severity": "p0"}]}
                ]
            },
            "not one of",
        ),
        ({"notes": "one note"}, "notes: a list expected"),
        ({"cleared": {"10.0.0.5": "CVE-1"}}, "a list expected"),
    ],
)
def test_a_reply_of_the_wrong_shape_is_refused(data: dict[str, Any], error: str) -> None:
    with pytest.raises(WireError, match=error):
        decode(ScanResult, data, "ScanResult")


# --- the child process ------------------------------------------------------------------------


def test_the_package_never_runs_in_zuesscan(probe: Site) -> None:
    plugin = built(probe)
    [note] = ask(plugin, "env").notes
    facts = json.loads(note)
    assert facts["pid"] != os.getpid() and facts["loaded_in"] == facts["pid"]
    assert MODULE not in sys.modules  # not when its spec was read, not when it ran
    assert plugin.version().startswith("1.0.0 pid ")


def test_it_runs_with_a_clean_environment_in_an_empty_folder(
    probe: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZUES_WEBHOOK_SECRET", "s3cret-of-the-service")
    monkeypatch.setenv("ZUES_DB", "/data/zues.db")
    monkeypatch.setenv("ZUES_INTERACTSH_TOKEN", "the-oast-server-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "abc")
    [note] = ask(built(probe), "env").notes
    facts = json.loads(note)

    assert not [k for k in facts["env"] if k.startswith("ZUES_") and k != "ZUES_TOOLS_DIR"]
    assert "AWS_SECRET_ACCESS_KEY" not in facts["env"]
    assert Path(facts["cwd"]).resolve() == Path(facts["home"]).resolve() != Path.cwd().resolve()
    assert Path(facts["cwd"]).name.startswith("zues-plugin-")
    assert not Path(facts["cwd"]).exists()  # removed after the call
    assert str(probe.root) in facts["path"]  # found the package where ZuesScan found it


def test_what_it_prints_does_not_break_its_reply(probe: Site) -> None:
    result = ask(built(probe), "print")
    assert [a.findings[0].title for a in result.assets] == ["probe finding"]


@pytest.mark.parametrize(
    ("what", "message"),
    [
        ("crash", "probe failed: RuntimeError: boom"),
        ("exit", "probe failed: SystemExit: 3"),
        ("wrong-type", "check\\(\\) returned a dict, not a ScanResult"),
        ("unsendable", "a object cannot be sent"),
    ],
)
def test_a_plugin_that_breaks_is_a_scan_error(probe: Site, what: str, message: str) -> None:
    with pytest.raises(ScanError, match=message) as caught:
        ask(built(probe), what)
    assert caught.value.plugin == "probe"


def test_its_own_scan_error_comes_back_whole(probe: Site) -> None:
    with pytest.raises(ScanError, match="the tool failed") as caught:
        ask(built(probe), "scan-error")
    assert caught.value.stderr == "tool said no"
    assert caught.value.output == RawOutput("probe", "text", ("probe",), "half an output")


def test_a_reply_too_large_is_refused(probe: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process, "REPLY_LIMIT", 50_000)
    with pytest.raises(ScanError, match="answered more than"):
        ask(built(probe), "big")


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes

        kernel = ctypes.windll.kernel32
        handle = kernel.OpenProcess(0x1000, False, pid)  # query limited information
        if not handle:
            return False
        code = ctypes.c_ulong()
        kernel.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.is_file() and stat.read_text().split(")")[-1].split()[0] == "Z")


def test_out_of_time_it_is_stopped_with_what_it_started(
    probe: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process, "GRACE", 3.0)
    plugin = built(probe, timeout=1)
    plugin.is_available()  # the probe has its own, longer limit
    started = time.monotonic()
    with pytest.raises(ScanError, match="no answer within 4 s: stopped") as caught:
        ask(plugin, "sleep")
    assert time.monotonic() - started < 30
    # What it printed before it was stopped is kept (stderr), here the program it started.
    grandchild = int((caught.value.stderr or "").split("grandchild ")[1].split()[0])
    deadline = time.monotonic() + 10
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _alive(grandchild)


def test_the_child_checks_the_pin_again_before_importing(probe: Site) -> None:
    plugin = built(probe, pinned(probe))  # verified, spec read
    (probe.root / MODULE / "__init__.py").write_text(
        SOURCE + "\nraise SystemExit('changed after it was checked')\n", encoding="utf-8"
    )
    assert plugin.is_available()  # a child that cannot start it: the call says why
    with pytest.raises(ScanError, match="PinError: the files of zues-probe 1.0.0 differ"):
        ask(plugin, "assets")


def test_a_broken_package_is_left_out_with_the_reason(site: Site) -> None:
    site.install(source="import a_module_nobody_installed\n")
    loaded = registry.load(site.entries)
    assert "probe" not in loaded.plugins
    assert "No module named 'a_module_nobody_installed'" in loaded.problems[0]


def test_its_spec_is_read_once_per_pinned_release(
    probe: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = pinned(probe)
    registry._DESCRIBED.clear()
    calls: list[str] = []
    real = process.describe

    def counted(ref: process.Ref) -> dict[str, Any]:
        calls.append(ref.name)
        return real(ref)

    monkeypatch.setattr(process, "describe", counted)
    for _ in range(3):
        assert "probe" in registry.load(probe.entries, policy).plugins
    assert calls == ["probe"]  # the web server lists plugins on every Settings page
    registry.load(probe.entries)  # no pin, no digest: read again, never cached
    assert calls == ["probe", "probe"]


# --- confined on Linux (Landlock) ------------------------------------------------------------

needs_landlock = pytest.mark.skipif(landlock.abi() == 0, reason="needs Linux with Landlock")


@needs_landlock
def test_on_linux_it_reads_and_writes_only_what_it_was_given(
    probe: Site, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZUES_WEBHOOK_SECRET", "s3cret-of-the-service")
    database = tmp_path / "zues.db"  # next to the package's folder, not inside it
    database.write_text("every finding", encoding="utf-8")
    plugin = built(probe)
    [note] = ask(plugin, "files", str(database)).notes

    assert json.loads(note) == {
        "read the database": "PermissionError",
        "write beside it": "PermissionError",
        "write at home": "ok",
        "read os-release": "ok",
        "read ZuesScan's environment": "PermissionError",
        "cat the database": "CalledProcessError",  # what it starts is confined too
        "run a program": "ok",
    }
    assert plugin.confined == landlock.abi()
    assert not (tmp_path / "zues.db.new").exists()


def test_what_a_confined_plugin_may_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    ref = process.Ref("probe", "zues_probe:PLUGIN", roots=(str(tmp_path / "site-packages"),))
    templates = tmp_path / "templates"
    paths = process.readable(ref, {"nuclei_templates": str(templates), "dns_wordlist": None})

    assert os.path.realpath(tmp_path / "site-packages") in paths
    assert os.path.realpath(templates) in paths
    assert os.path.realpath(Path(process.__file__).parent.parent) in paths  # zues_scan
    assert os.path.realpath(tmp_path) not in paths  # the working folder, where zues.db is
    assert os.path.realpath(Path.home()) not in paths
    assert os.path.realpath("/etc") not in paths and os.path.realpath("/etc/resolv.conf") in paths


def test_doctor_says_whether_plugins_are_confined() -> None:
    from zues_scan import doctor

    assert doctor.check_confinement("Linux", 3).status == doctor.OK
    linux = doctor.check_confinement("Linux", 0)
    assert linux.status == doctor.WARN and "this kernel has no Landlock" in linux.detail
    windows = doctor.check_confinement("Windows", 0)
    assert "not available on Windows" in windows.detail and "container" in (windows.hint or "")


def test_without_landlock_confine_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(landlock, "abi", lambda: 0)
    assert landlock.confine(["/usr"], ["/tmp"]) == 0
    assert landlock.handled(1) == (1 << 13) - 1
    assert landlock.handled(5) & landlock.IOCTL_DEV and landlock.handled(3) & landlock.TRUNCATE


# --- end to end -------------------------------------------------------------------------------


def test_a_scan_with_a_package_check_records_its_findings(
    probe: Site, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("zues_scan.scope.resolve_addresses", lab_resolver)
    monkeypatch.setattr(
        "zues_scan.plugins.registry.NmapPlugin",
        lambda **_: FakePlugin([lab_asset(Service(80, name="http"))]),
    )
    monkeypatch.setattr(registry, "_entry_points", probe.entries)
    monkeypatch.delenv("ZUES_PLUGINS", raising=False)
    (tmp_path / "scope.txt").write_text("10.0.0.0/24\n", encoding="utf-8")
    db = tmp_path / "r.db"

    outcome = execute(
        ScanSpec("10.0.0.5", str(tmp_path / "scope.txt"), db=str(db), checks=["probe"])
    )
    assert outcome.code == 0, outcome.messages
    assert outcome.run is not None
    assert str(outcome.run.tool_versions["probe"]).startswith("1.0.0 pid ")
    with Storage(db) as store:
        run = store.load_run(outcome.run_id or 0)
    assert run is not None
    titles = [f.title for a in run.assets for f in a.findings]
    assert "probe finding" in titles
    assert any(raw.plugin == "probe" and raw.content == "checked" for raw in run.raw_outputs)
    assert MODULE not in sys.modules


def test_a_package_check_granted_more_still_runs_in_a_child(probe: Site) -> None:
    plugin = built(probe, pinned(probe, "active"))
    assert plugin.activity is Activity.ACTIVE  # what the scope gate reads
    assert [a.findings[0].rule_id for a in ask(plugin, "assets").assets] == ["probe"]
