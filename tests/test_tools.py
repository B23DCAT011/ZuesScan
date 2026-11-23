"""zues tools: nuclei, subfinder and templates installed by ZuesScan — exactly the
locked files, or nothing — and found before anything on PATH."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from zues_scan import cli, tools
from zues_scan.plugins import nuclei
from zues_scan.tools import Entry, ToolError


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tgz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _entry(tool: str, data: bytes, where: str = "linux-amd64", version: str = "1.0.0") -> Entry:
    return Entry(
        tool, version, where, hashlib.sha256(data).hexdigest(), f"https://x/{tool}/{where}"
    )


NUCLEI = _zip({"nuclei": b"\x7fELF nuclei", "README.md": b"docs", "../evil": b"no"})
NUCLEI_EXE = _zip({"nuclei.exe": b"MZ nuclei", "LICENSE.md": b"MIT"})
SUBFINDER = _zip({"subfinder": b"\x7fELF subfinder"})
DNSX = _zip({"dnsx": b"\x7fELF dnsx"})
NAABU = _zip({"naabu": b"\x7fELF naabu"})
TEMPLATES = _tgz(
    {
        "nuclei-templates-10.5.2/http/cves/2021/CVE-2021-41773.yaml": b"id: CVE-2021-41773\n",
        "nuclei-templates-10.5.2/.nuclei-ignore": b"tags:\n  - dos\n",
        "nuclei-templates-10.5.2/.github/workflows/ci.yml": b"on: push\n",
        "nuclei-templates-10.5.2/README.md": b"# docs\n",
    }
)
ENTRIES = [
    _entry("nuclei", NUCLEI),
    _entry("nuclei", NUCLEI_EXE, "windows-amd64"),
    _entry("subfinder", SUBFINDER),
    _entry("dnsx", DNSX),
    _entry("naabu", NAABU),
    _entry("nuclei-templates", TEMPLATES, "any", "10.5.2"),
]
SERVED = dict(
    zip(
        (e.url for e in ENTRIES),
        (NUCLEI, NUCLEI_EXE, SUBFINDER, DNSX, NAABU, TEMPLATES),
        strict=True,
    )
)


# --- the lock -----------------------------------------------------------------------------------


def test_the_real_lock_covers_every_platform() -> None:
    entries = tools.read_lock()
    for where in tools.PLATFORMS:
        assert set(tools.for_platform(entries, where)) == set(tools.TOOLS), where
    assert all(e.url.startswith("https://github.com/projectdiscovery/") for e in entries)


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("nuclei 1 linux-amd64 abc https://x", "bad sha256"),
        ("nuclei 1 linux-amd64 " + "a" * 64 + " http://x", "must be https"),
        ("nuclei 1 plan9-386 " + "a" * 64 + " https://x", "unknown platform"),
        ("nuclei 1 linux-amd64", "expected 5 fields"),
    ],
)
def test_a_bad_lock_line_is_refused(line: str, error: str) -> None:
    with pytest.raises(ToolError, match=error):
        tools.parse_lock(line)


# --- installing ---------------------------------------------------------------------------------


def test_install_takes_exactly_the_locked_files(tmp_path: Path) -> None:
    done = tools.install(ENTRIES, tmp_path, "linux-amd64", get=SERVED.__getitem__)

    assert len(done) == 5  # the Windows build was not fetched
    assert sorted(p.name for p in (tmp_path / "bin").iterdir()) == [
        "dnsx",
        "naabu",
        "nuclei",
        "subfinder",
    ]
    assert (tmp_path / "bin" / "nuclei").read_bytes() == b"\x7fELF nuclei"
    assert not (tmp_path / "evil").exists()  # only the binary leaves the zip
    tpl = tmp_path / "nuclei-templates"
    assert (tpl / "http" / "cves" / "2021" / "CVE-2021-41773.yaml").is_file()
    assert (tpl / ".nuclei-ignore").is_file()
    assert not (tpl / ".github").exists() and not (tpl / "README.md").exists()
    assert (tpl / ".zues-version").read_text() == "10.5.2\n"
    manifest = tools.installed(tmp_path)
    assert manifest["nuclei"]["sha256"] == hashlib.sha256(b"\x7fELF nuclei").hexdigest()
    assert manifest["nuclei-templates"]["version"] == "10.5.2"
    assert tools.verify(tmp_path) == []


def test_windows_gets_the_exe(tmp_path: Path) -> None:
    tools.install(ENTRIES, tmp_path, "windows-amd64", ("nuclei",), get=SERVED.__getitem__)
    assert (tmp_path / "bin" / "nuclei.exe").read_bytes() == b"MZ nuclei"


def test_a_changed_download_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="differs from the locked"):
        tools.install(ENTRIES, tmp_path, "linux-amd64", ("nuclei",), get=lambda url: b"evil")
    assert not (tmp_path / "bin").exists()


def test_an_archive_escaping_its_folder_is_refused(tmp_path: Path) -> None:
    evil = _tgz({"nuclei-templates-1/ok.yaml": b"x", "../../outside.yaml": b"x"})
    with pytest.raises(tarfile.TarError):
        tools.install_templates(_entry("nuclei-templates", evil, "any"), evil, tmp_path / "tpl")
    assert not (tmp_path.parent / "outside.yaml").exists()


def test_nothing_for_this_platform(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="nuclei, subfinder, dnsx, naabu on darwin-arm64"):
        tools.install(ENTRIES, tmp_path, "darwin-arm64", get=SERVED.__getitem__)


def test_verify_notices_changes(tmp_path: Path) -> None:
    tools.install(ENTRIES, tmp_path, "linux-amd64", get=SERVED.__getitem__)
    (tmp_path / "bin" / "nuclei").write_bytes(b"\x7fELF replaced")
    yaml = tmp_path / "nuclei-templates" / "http" / "cves" / "2021" / "CVE-2021-41773.yaml"
    yaml.write_text("id: CVE-2021-41773\n# edited\n", encoding="utf-8")
    (tmp_path / "bin" / "subfinder").unlink()
    problems = tools.verify(tmp_path)
    assert any(p.startswith("nuclei: ") and "changed" in p for p in problems)
    assert any(p.startswith("nuclei-templates: ") and "changed" in p for p in problems)
    assert any(p.startswith("subfinder: ") and "is gone" in p for p in problems)


# --- where ZuesScan looks -----------------------------------------------------------------------


def test_zues_own_copy_comes_before_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZUES_TOOLS_DIR", str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    assert tools.which("nuclei") == "/usr/bin/nuclei"
    assert tools.resolve("nuclei") == "nuclei"  # PATH finds it: the command stays "nuclei"

    own = tmp_path / "bin" / ("nuclei.exe" if sys.platform == "win32" else "nuclei")
    own.parent.mkdir()
    own.write_bytes(b"binary")
    assert tools.which("nuclei") == str(own)  # the pinned copy wins
    assert tools.resolve("nuclei") == str(own)


def test_nmap_installed_on_windows_is_found_without_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "Nmap").mkdir()
    (tmp_path / "Nmap" / "nmap.exe").write_bytes(b"MZ")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    expected = str(tmp_path / "Nmap" / "nmap.exe")
    assert tools.which("nmap") == expected
    assert tools.resolve("nmap") == expected


def test_platform_and_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TARGETARCH", "arm64")
    monkeypatch.setattr(sys, "platform", "linux")
    assert tools.current_platform() == "linux-arm64"
    monkeypatch.delenv("ZUES_TOOLS_DIR")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert tools.default_root() == tmp_path / "zues" / "tools"


def test_installed_templates_are_used_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZUES_TOOLS_DIR", str(tmp_path))
    assert nuclei.default_templates() is None
    tools.install(ENTRIES, tmp_path, "linux-amd64", ("nuclei-templates",), get=SERVED.__getitem__)
    assert nuclei.default_templates() == str(tmp_path / "nuclei-templates")
    monkeypatch.setenv("ZUES_NUCLEI_TEMPLATES", "/opt/nuclei-templates")  # the image's wins
    assert nuclei.default_templates() == "/opt/nuclei-templates"


# --- updating the lock --------------------------------------------------------------------------

API = "https://api.github.com/repos/projectdiscovery"
DL = "https://github.com/projectdiscovery"


def _sums(*names: str) -> bytes:
    return "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in names).encode()


def test_update_takes_every_platform_from_the_checksums() -> None:
    def files(tool: str, version: str) -> bytes:
        return _sums(*(f"{tool}_{version}_{s}.zip" for s in tools.PLATFORMS.values()))

    pages = {
        f"{API}/nuclei/releases/latest": b'{"tag_name":"v3.12.0"}',
        f"{API}/subfinder/releases/latest": b'{"tag_name":"v2.18.0"}',
        f"{API}/dnsx/releases/latest": b'{"tag_name":"v1.4.0"}',
        f"{API}/naabu/releases/latest": b'{"tag_name":"v2.8.0"}',
        f"{API}/nuclei-templates/releases/latest": b'{"tag_name":"v10.6.0"}',
        f"{DL}/nuclei/releases/download/v3.12.0/nuclei_3.12.0_checksums.txt": files(
            "nuclei", "3.12.0"
        ),
        f"{DL}/subfinder/releases/download/v2.18.0/subfinder_2.18.0_checksums.txt": files(
            "subfinder", "2.18.0"
        ),
        # Some releases name the file differently (naabu: naabu-checksums.txt).
        f"{DL}/dnsx/releases/download/v1.4.0/dnsx-checksums.txt": files("dnsx", "1.4.0"),
        f"{DL}/naabu/releases/download/v2.8.0/naabu_2.8.0_checksums.txt": files("naabu", "2.8.0"),
        f"{DL}/nuclei-templates/releases/download/v10.6.0/nuclei-templates-10.6.0_checksums.txt": (
            _sums("nuclei-templates-10.6.0.tar.gz")
        ),
    }

    def get(url: str) -> bytes:
        if url not in pages:
            raise OSError(f"HTTP Error 404: {url}")  # what urllib raises (HTTPError)
        return pages[url]

    entries = tools.parse_lock("\n".join(tools.lock_lines(get)))

    assert len(entries) == len(tools.BINARIES) * len(tools.PLATFORMS) + 1
    dnsx = next(e for e in entries if e.tool == "dnsx" and e.platform == "linux-arm64")
    assert dnsx.url.endswith("/v1.4.0/dnsx_1.4.0_linux_arm64.zip")
    mac = next(e for e in entries if e.tool == "nuclei" and e.platform == "darwin-arm64")
    assert mac.url.endswith("nuclei_3.12.0_macOS_arm64.zip")
    assert mac.sha256 == hashlib.sha256(b"nuclei_3.12.0_macOS_arm64.zip").hexdigest()


def test_update_refuses_a_release_without_the_checksum() -> None:
    pages = {
        f"{API}/nuclei/releases/latest": b'{"tag_name":"v3.12.0"}',
        f"{DL}/nuclei/releases/download/v3.12.0/nuclei_3.12.0_checksums.txt": b"",
    }
    with pytest.raises(ToolError, match="no checksum for nuclei_3.12.0_linux_amd64.zip"):
        tools.lock_lines(pages.__getitem__)


# --- the command ----------------------------------------------------------------------------------


def test_cli_install_list_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    here = tools.current_platform()
    exe = ".exe" if here.startswith("windows") else ""
    archives = {
        "nuclei": _zip({f"nuclei{exe}": b"nuclei"}),
        "subfinder": _zip({f"subfinder{exe}": b"subfinder"}),
    }
    entries = [_entry(tool, data, here) for tool, data in archives.items()]
    entries.append(_entry("nuclei-templates", TEMPLATES, "any", "10.5.2"))
    served = dict(zip((e.url for e in entries), (*archives.values(), TEMPLATES), strict=True))
    monkeypatch.setattr(tools, "read_lock", lambda path=None: entries)
    monkeypatch.setattr(tools, "fetch", served.__getitem__)
    root = str(tmp_path / "tools")

    assert cli.main(["tools", "--root", root, "install", "nuclei", "nuclei-templates"]) == 0
    assert "nuclei 1.0.0" in capsys.readouterr().out
    assert cli.main(["tools", "--root", root, "list", "--json"]) == 0
    listed = {r["tool"]: r for r in json.loads(capsys.readouterr().out)["tools"]}
    assert listed["nuclei"]["installed"] == "1.0.0" and listed["subfinder"]["installed"] is None
    assert cli.main(["tools", "--root", root, "verify"]) == 0
    assert cli.main(["tools", "--root", root, "path"]) == 0
    assert capsys.readouterr().out.strip().endswith(str(Path(root) / "bin"))
    assert cli.main(["tools", "--root", root, "install", "masscan"]) == 2
    assert "unknown tool(s) masscan" in capsys.readouterr().err
