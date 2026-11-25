"""Plugins from other packages run in a process of their own (G25).

A plugin package's code never runs inside ZuesScan: not when its spec is read, not when it
scans. Every call — `describe` (its PluginSpec), `probe` (is_available + version), `scan`,
`check`, `discover` — is one child process, `python -I -m zues_scan.plugins.process`, that
reads the call as JSON on stdin and answers on stdout. `ProcessPlugin` stands in for the
plugin in the orchestrator; `main()` is the child.

What the child gets: the call's own data (the addresses the scope approved, the hosts to
check), the scan profile, the paths of the nuclei templates and the DNS wordlist. What it
does not get: ZuesScan's environment (no ZUES_* variable: database, Redis, webhook secret,
tokens), the database or the CVE cache, SSH credentials, subfinder's API keys, the
service's working directory. It runs in an empty temporary folder that is also its HOME,
under the scan's time limit; its reply and error output are capped, and when it runs out
of time its whole process group (the tools it started too) is killed. Before importing the
plugin, the child checks the package against its pin again, from the files on disk.

Its reply is untrusted input: decoded field by field (`wire.decode`), then held to the same
rules as any plugin's (the orchestrator drops hosts outside the scope).

On Linux, the child then confines itself with Landlock (`landlock`, no root needed)
before importing the plugin: it — and every program it starts — can read only the system,
Python, its own package, ZuesScan's tools and the scan's templates and wordlist, and write
only its temporary folder. The database, the service configuration and credentials are out
of reach, and so is the service's own process (/proc/<pid>/environ). If the kernel has
Landlock but the confinement fails, the call fails: it never goes on unconfined.

What it still can: connect anywhere; and where the kernel has no Landlock (or on Windows
and macOS), read any file the service's user can. That needs a container of its own (see
KNOWN-GAPS G25).

Each call is a fresh process: a plugin keeps no state from one call to the next.
"""

from __future__ import annotations

import contextlib
import functools
import json
import os
import shutil
import signal
import site
import subprocess
import sys
import sysconfig
import tempfile
import threading
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from typing import Any, TypeVar

import zues_scan
from zues_scan import tools
from zues_scan.plugins import landlock
from zues_scan.plugins.base import DiscoveryResult, ScanError, ScanResult
from zues_scan.plugins.wire import WireError, decode, encode
from zues_scan.profiles import ScanProfile
from zues_scan.schema import Asset, RawOutput, ScanTarget
from zues_scan.scope import Activity, ScopeError

PROTOCOL = 1
REPLY_LIMIT = 128 * 1024 * 1024  # bytes a child may answer (raw output included)
STDERR_KEPT = 64 * 1024  # the last bytes of its error output, kept for the person
MESSAGE_KEPT = 2000  # characters of an error message it sends
SETUP_TIMEOUT = 60.0  # seconds for describe / probe (importing the package included)
GRACE = 60.0  # seconds past the profile's timeout before a scan call is stopped
# Variables a child needs to run programs at all, and nothing that says where ZuesScan
# keeps its data or secrets.
_PASSED_ENV = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "NMAP_PRIVILEGED",
)
KINDS = ("scanner", "check", "discovery")
# What a confined plugin may read besides Python, its package and the scan's files: the
# system's programs and libraries, and what programs need from /etc to resolve names,
# verify certificates and know users and time — not /etc as a whole, where a service's
# configuration may live.
_SYSTEM = ("/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/proc", "/sys")
_ETC = (
    "resolv.conf",
    "hosts",
    "host.conf",
    "nsswitch.conf",
    "gai.conf",
    "services",
    "protocols",
    "passwd",
    "group",
    "localtime",
    "timezone",
    "ssl",
    "ca-certificates",
    "ca-certificates.conf",
    "pki",
    "crypto-policies",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "os-release",
    "mime.types",
)
T = TypeVar("T")


@dataclass(frozen=True)
class Ref:
    """Which plugin a child loads: the entry point, as the child finds it again among the
    installed packages, and the pin it must still match (None: no policy)."""

    name: str
    value: str
    pin: dict[str, str] | None = None
    sys_path: tuple[str, ...] = ()
    roots: tuple[str, ...] = ()  # where its package is installed (readable when confined)


def readable(ref: Ref, args: dict[str, Any]) -> list[str]:
    """What a confined child may read: the system, Python (prefixes, stdlib, site
    folders), ZuesScan's own package, the plugin's package, ZuesScan's tools, and the
    scan's nuclei templates and DNS wordlist. Not the working directory, HOME, /etc as a
    whole, the database's or the configuration's folder."""
    paths: list[str | None] = [*_SYSTEM, *(f"/etc/{name}" for name in _ETC)]
    paths += [sys.prefix, sys.base_prefix, sys.exec_prefix]
    paths.append(os.path.dirname(os.path.realpath(sys.executable)))
    folders = sysconfig.get_paths()
    paths += [folders.get(k) for k in ("stdlib", "platstdlib", "purelib", "platlib", "scripts")]
    with contextlib.suppress(AttributeError):  # some virtualenvs' site has no such function
        paths += site.getsitepackages()
    paths.append(os.path.dirname(os.path.abspath(zues_scan.__file__)))
    paths += ref.roots
    paths.append(str(tools.default_root()))
    paths += [args.get("nuclei_templates"), args.get("dns_wordlist")]
    return sorted({os.path.realpath(p) for p in paths if p})


# --- the parent side ----------------------------------------------------------------------------


def call(ref: Ref, op: str, args: dict[str, Any], timeout: float, plugin: str) -> Any:
    """One call in a child process; its result, or ScanError saying what went wrong."""
    request = {
        "protocol": PROTOCOL,
        "op": op,
        "entry": {"name": ref.name, "value": ref.value},
        "pin": ref.pin,
        "sys_path": list(ref.sys_path or [p for p in sys.path if p]),
        "args": args,
    }
    home = tempfile.mkdtemp(prefix="zues-plugin-")
    request["confine"] = {"read": readable(ref, args), "write": [home, "/dev"]}
    try:
        reply, stderr, code, trouble = _run(
            json.dumps(request).encode("utf-8"), home, timeout, plugin
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)
    tail = stderr.decode("utf-8", "replace").strip() or None
    if trouble is not None:
        raise ScanError(trouble, plugin=plugin, stderr=tail)
    try:
        answer = json.loads(reply)
    except (ValueError, RecursionError):
        raise ScanError(
            f"{plugin} did not answer (its process exited with code {code})",
            plugin=plugin,
            stderr=tail,
        ) from None
    if not isinstance(answer, dict) or answer.get("protocol") != PROTOCOL:
        raise ScanError(f"{plugin} answered something that is not a reply", plugin=plugin)
    if answer.get("ok") is True:
        return answer.get("result")
    error: dict[str, Any] = answer["error"] if isinstance(answer.get("error"), dict) else {}
    message = str(error.get("message") or "no reason given")[:MESSAGE_KEPT]
    if error.get("kind") == "scan":
        try:
            output = decode(RawOutput | None, error.get("output"), "error.output")
        except WireError:
            output = None
        raise ScanError(
            message,
            plugin=plugin,
            stderr=str(error["stderr"])[-STDERR_KEPT:] if error.get("stderr") else tail,
            output=output,
            no_response=error.get("no_response") is True,
        )
    raise ScanError(f"{plugin} failed: {message}", plugin=plugin, stderr=tail)


def _run(
    request: bytes, home: str, timeout: float, plugin: str
) -> tuple[bytes, bytes, int | None, str | None]:
    """Start the child, give it the request, collect what it says (capped), stop it and
    everything it started when the time is up. Returns stdout, the end of stderr, the exit
    code and, if it had to be stopped, why."""
    try:
        proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "zues_scan.plugins.process"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=home,
            env=_environment(home),
            **_own_group(),
        )
    except OSError as exc:
        return b"", b"", None, f"could not start a process for {plugin}: {exc}"
    out = bytearray()
    err = bytearray()
    trouble: list[str] = []

    def read_reply() -> None:
        assert proc.stdout is not None
        while chunk := os.read(proc.stdout.fileno(), 1 << 16):
            if len(out) + len(chunk) > REPLY_LIMIT:
                trouble.append(f"{plugin} answered more than {REPLY_LIMIT >> 20} MiB: stopped")
                _stop(proc)
                return
            out.extend(chunk)

    def read_errors() -> None:
        assert proc.stderr is not None
        while chunk := os.read(proc.stderr.fileno(), 1 << 16):
            err.extend(chunk)
            del err[:-STDERR_KEPT]

    readers = [threading.Thread(target=f, daemon=True) for f in (read_reply, read_errors)]
    for reader in readers:
        reader.start()
    assert proc.stdin is not None
    with contextlib.suppress(OSError):  # it may exit before reading: its reply says why
        proc.stdin.write(request)
        proc.stdin.close()
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        trouble.append(
            f"{plugin} gave no answer within {timeout:.0f} s: stopped, with the programs it started"
        )
        _stop(proc)
        proc.wait()
    for reader in readers:
        reader.join(10)
    _stop(proc)  # what it left running in its group (POSIX)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()
    return bytes(out), bytes(err), proc.returncode, trouble[0] if trouble else None


def _environment(home: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in _PASSED_ENV if k in os.environ}
    env.update(
        {
            "HOME": home,
            "USERPROFILE": home,
            "APPDATA": home,
            "LOCALAPPDATA": home,
            "XDG_CONFIG_HOME": home,
            "XDG_CACHE_HOME": home,
            "TMPDIR": home,
            "TEMP": home,
            "TMP": home,
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            # Where `zues tools install` put nmap / nuclei: a path, not a secret, and
            # tools.which() would look under the new HOME otherwise.
            "ZUES_TOOLS_DIR": str(tools.default_root()),
        }
    )
    return env


def _own_group() -> dict[str, Any]:
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        return {"creationflags": flags}
    return {"start_new_session": True}


def _stop(proc: subprocess.Popen[bytes]) -> None:
    """Kill the child and what it started: its process group (POSIX), its process tree
    (Windows: taskkill /T, while the child is still there to find its children)."""
    if sys.platform == "win32":
        if proc.poll() is None:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                check=False,
            )
            with contextlib.suppress(OSError):
                proc.kill()
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def describe(ref: Ref) -> dict[str, Any]:
    """The plugin's spec, read in a child: name, kind, activity, summary, binary, needs."""
    result = call(ref, "describe", {}, SETUP_TIMEOUT, ref.name)
    try:
        spec = decode(_Described, result, "spec")
    except WireError as exc:
        raise ScanError(f"its spec cannot be read: {exc}", plugin=ref.name) from None
    if spec.kind not in KINDS:
        raise ScanError(f"its kind {spec.kind!r} is not one of {', '.join(KINDS)}", plugin=ref.name)
    try:
        activity = Activity.parse(spec.activity)
    except ScopeError as exc:
        raise ScanError(str(exc), plugin=ref.name) from None
    return {
        "name": spec.name,
        "kind": spec.kind,
        "activity": activity,
        "summary": spec.summary[:200],
        "binary": spec.binary,
        "needs": tuple(n[:100] for n in spec.needs[:10]),
        "confined": spec.confined,
    }


@dataclass(frozen=True)
class _Described:
    name: str
    kind: str
    activity: str
    summary: str
    binary: str | None
    needs: tuple[str, ...]
    confined: int  # the Landlock version the child ran under; 0: not confined


class ProcessPlugin:
    """A plugin from another package, as the orchestrator sees it: each call runs it in a
    child process (see the module). Built by its spec's factory, for one scan."""

    def __init__(self, ref: Ref, name: str, activity: Activity, ctx: Any) -> None:
        self._ref = ref
        self.name = name
        self.activity = activity  # what it declares; the registry wraps what was granted
        self._context = {
            "profile": encode(ctx.profile),
            "nuclei_templates": ctx.nuclei_templates,
            "dns_wordlist": ctx.dns_wordlist,
        }
        self._timeout = float(ctx.profile.timeout) + GRACE
        self._probed: dict[str, Any] | ScanError | None = None

    def _call(self, op: str, args: dict[str, Any], timeout: float | None = None) -> Any:
        return call(self._ref, op, {**self._context, **args}, timeout or self._timeout, self.name)

    def _probe(self) -> dict[str, Any] | ScanError:
        if self._probed is None:
            try:
                answer = self._call("probe", {}, SETUP_TIMEOUT)
                if not isinstance(answer, dict):
                    raise ScanError("its probe answered no object", plugin=self.name)
                self._probed = answer
            except ScanError as exc:
                self._probed = exc
        return self._probed

    def is_available(self) -> bool:
        # A child that fails to start the plugin counts as available: the call that
        # follows fails with the reason, instead of the plugin being skipped in silence.
        probed = self._probe()
        return True if isinstance(probed, ScanError) else probed.get("available") is True

    def version(self) -> str | None:
        probed = self._probe()
        if isinstance(probed, ScanError):
            return None
        version = probed.get("version")
        return version[:100] if isinstance(version, str) else None

    @property
    def confined(self) -> int | None:
        """The Landlock version its calls run under (0: not confined); None: unknown."""
        probed = self._probe()
        value = None if isinstance(probed, ScanError) else probed.get("confined")
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def _broken(self) -> None:
        if isinstance(self._probed, ScanError):
            raise self._probed

    def scan(self, target: ScanTarget) -> ScanResult:
        self._broken()
        return self._result(ScanResult, self._call("scan", {"target": encode(target)}))

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        self._broken()
        args = {"plan": encode(plan), "assets": encode(assets)}
        return self._result(ScanResult, self._call("check", args))

    def discover(self, domain: str) -> DiscoveryResult:
        self._broken()
        return self._result(DiscoveryResult, self._call("discover", {"domain": domain}))

    def _result(self, cls: type[T], data: Any) -> T:
        try:
            result: T = decode(cls, data, cls.__name__)
            return result
        except WireError as exc:
            raise ScanError(
                f"{self.name} sent a result ZuesScan cannot use: {exc}", plugin=self.name
            ) from None


def factory(ref: Ref, name: str, activity: Activity) -> Callable[[Any], ProcessPlugin]:
    return functools.partial(ProcessPlugin, ref, name, activity)


# --- the child side -----------------------------------------------------------------------------


def main() -> int:
    """Run one call of a plugin: the request on stdin, the reply on stdout."""
    reply_fd = os.dup(1)
    os.dup2(2, 1)  # whatever the plugin prints goes to stderr, never into the reply
    request_bytes = sys.stdin.buffer.read()
    nothing = os.open(os.devnull, os.O_RDONLY)
    os.dup2(nothing, 0)  # programs it starts get no stdin of ours
    try:
        reply: dict[str, Any] = {"protocol": PROTOCOL, "ok": True}
        reply["result"] = _serve(json.loads(request_bytes))
        data = json.dumps(reply)
    except ScanError as exc:
        data = json.dumps(_scan_error(exc))
    except BaseException as exc:  # noqa: BLE001 - whatever it was, say so (sys.exit too)
        traceback.print_exc()
        message = f"{type(exc).__name__}: {exc}"
        data = json.dumps(
            {"protocol": PROTOCOL, "ok": False, "error": {"kind": "crash", "message": message}}
        )
    with os.fdopen(reply_fd, "wb") as out:
        out.write(data.encode("utf-8"))
    return 0


def _scan_error(exc: ScanError) -> dict[str, Any]:
    try:
        output = encode(exc.output)
    except WireError:
        output = None
    return {
        "protocol": PROTOCOL,
        "ok": False,
        "error": {
            "kind": "scan",
            "message": str(exc),
            "stderr": exc.stderr,
            "output": output,
            "no_response": exc.no_response,
        },
    }


def _serve(request: Any) -> Any:
    from zues_scan.plugins import registry

    if not isinstance(request, dict) or request.get("protocol") != PROTOCOL:
        raise RuntimeError("not a request of this version of ZuesScan")
    sys.path[:] = [str(p) for p in request["sys_path"]]
    rules = request.get("confine") or {}
    try:  # before anything of the plugin is imported: its code runs confined, or not at all
        confined = landlock.confine(rules.get("read", ()), rules.get("write", ()))
    except OSError as exc:
        raise RuntimeError(f"the plugin's process could not be confined: {exc}") from None
    spec = _load(registry, request["entry"], request.get("pin"))
    op, args = request["op"], request.get("args") or {}
    if op == "describe":
        return {
            "name": spec.name,
            "kind": spec.kind,
            "activity": str(spec.activity),
            "summary": spec.summary,
            "binary": spec.binary,
            "needs": list(spec.needs),
            "confined": confined,
        }
    ctx = registry.PluginContext(
        profile=decode(ScanProfile, args["profile"], "profile"),
        nuclei_templates=args.get("nuclei_templates"),
        dns_wordlist=args.get("dns_wordlist"),
    )
    plugin = spec.factory(ctx)
    if getattr(plugin, "name", None) is None:
        raise registry.PluginError("its factory built an object without a name")
    if getattr(plugin, "activity", spec.activity) != spec.activity:
        raise registry.PluginError("its activity differs from what it declares")
    if op == "probe":
        return {
            "available": bool(plugin.is_available()),
            "version": _version(plugin),
            "confined": confined,
        }
    if op == "scan":
        result = plugin.scan(decode(ScanTarget, args["target"], "target"))
        expected: type[Any] = ScanResult
    elif op == "check":
        plan = decode(ScanTarget, args["plan"], "plan")
        result = plugin.check(plan, decode(list[Asset], args["assets"], "assets"))
        expected = ScanResult
    elif op == "discover":
        result = plugin.discover(str(args["domain"]))
        expected = DiscoveryResult
    else:
        raise RuntimeError(f"unknown call {op!r}")
    if not isinstance(result, expected):
        raise registry.PluginError(
            f"{op}() returned a {type(result).__name__}, not a {expected.__name__}"
        )
    return encode(result)


def _load(registry: Any, entry: dict[str, str], pin: dict[str, str] | None) -> Any:
    """The plugin's spec, from the installed entry point the parent named — held to its
    pin again first, in this process, from the files on disk."""
    found = [
        e
        for e in metadata.entry_points(group=registry.GROUP)
        if e.name == entry["name"] and e.value == entry["value"]
    ]
    if not found:
        raise registry.PluginError(
            f"no installed package provides {entry['name']} = {entry['value']} any more"
        )
    if pin is not None:
        held = registry.Pin(**{**pin, "activity": Activity.parse(pin["activity"])})
        registry.verify(found[0], held)
    return registry.spec_of(found[0].load())


def _version(plugin: Any) -> str | None:
    try:
        version = plugin.version()
    except Exception:  # noqa: BLE001 - version() must not raise; treat it as unknown
        return None
    return None if version is None else str(version)


if __name__ == "__main__":
    sys.exit(main())
