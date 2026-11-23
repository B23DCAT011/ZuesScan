"""docker/tools.py: the image's external tools are what the lock says, or nothing."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    path = Path(__file__).parent.parent / "docker" / "tools.py"
    spec = importlib.util.spec_from_file_location("docker_tools", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while defined
    spec.loader.exec_module(module)
    return module


tools = _load()


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


def _entry(tool: str, data: bytes, arch: str = "amd64", version: str = "1.0.0") -> object:
    return tools.Entry(tool, version, arch, hashlib.sha256(data).hexdigest(), f"https://x/{tool}")


NUCLEI = _zip({"nuclei": b"\x7fELF nuclei", "README.md": b"docs", "../evil": b"no"})
SUBFINDER = _zip({"subfinder": b"\x7fELF subfinder"})
TEMPLATES = _tgz(
    {
        "nuclei-templates-10.5.2/http/cves/2021/CVE-2021-41773.yaml": b"id: CVE-2021-41773\n",
        "nuclei-templates-10.5.2/.nuclei-ignore": b"tags:\n  - dos\n",
        "nuclei-templates-10.5.2/.github/workflows/ci.yml": b"on: push\n",
        "nuclei-templates-10.5.2/README.md": b"# docs\n",
    }
)


def test_the_real_lock_is_well_formed() -> None:
    entries = tools.parse_lock(tools.LOCK.read_text(encoding="utf-8"))
    names = {(e.tool, e.arch) for e in entries}
    for arch in tools.ARCHES:
        assert {("nuclei", arch), ("subfinder", arch)} <= names
    assert ("nuclei-templates", "any") in names
    assert all(e.url.startswith("https://github.com/projectdiscovery/") for e in entries)


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("nuclei 1 amd64 abc https://x", "bad sha256"),
        ("nuclei 1 amd64 " + "a" * 64 + " http://x", "must be https"),
        ("nuclei 1 amd64", "expected 5 fields"),
    ],
)
def test_a_bad_lock_line_is_refused(line: str, error: str) -> None:
    with pytest.raises(tools.ToolError, match=error):
        tools.parse_lock(line)


def test_install_checks_every_hash_and_takes_only_the_binaries(tmp_path: Path) -> None:
    entries = [
        _entry("nuclei", NUCLEI),
        _entry("nuclei", b"other arch", arch="arm64"),
        _entry("subfinder", SUBFINDER),
        _entry("nuclei-templates", TEMPLATES, arch="any", version="10.5.2"),
    ]
    served = {"https://x/nuclei": NUCLEI, "https://x/subfinder": SUBFINDER}
    served["https://x/nuclei-templates"] = TEMPLATES

    done = tools.install(entries, tmp_path / "bin", tmp_path / "tpl", "amd64", served.__getitem__)

    assert len(done) == 3  # the arm64 build was not fetched
    assert sorted(p.name for p in (tmp_path / "bin").iterdir()) == ["nuclei", "subfinder"]
    assert (tmp_path / "bin" / "nuclei").read_bytes() == b"\x7fELF nuclei"
    assert not (tmp_path / "evil").exists()
    tpl = tmp_path / "tpl"
    assert (tpl / "http" / "cves" / "2021" / "CVE-2021-41773.yaml").is_file()
    assert (tpl / ".nuclei-ignore").is_file()  # kept: nuclei's default exclusions
    assert not (tpl / ".github").exists() and not (tpl / "README.md").exists()
    assert (tpl / ".reconkit-version").read_text() == "10.5.2\n"


def test_a_changed_file_is_refused(tmp_path: Path) -> None:
    entry = _entry("nuclei", NUCLEI)
    with pytest.raises(tools.ToolError, match="differs from the locked"):
        tools.download(entry, lambda url: NUCLEI + b"tampered")


def test_an_archive_escaping_its_folder_is_refused(tmp_path: Path) -> None:
    evil = _tgz({"nuclei-templates-1/ok.yaml": b"x", "../../outside.yaml": b"x"})
    entry = _entry("nuclei-templates", evil, arch="any")
    with pytest.raises(tarfile.TarError):
        tools.install_templates(entry, evil, tmp_path / "tpl")
    assert not (tmp_path.parent / "outside.yaml").exists()


def test_nothing_for_this_architecture_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(tools.ToolError, match="nothing for nuclei, subfinder"):
        tools.install(
            [_entry("nuclei-templates", TEMPLATES, arch="any")], tmp_path, tmp_path, "s390x"
        )


API = "https://api.github.com/repos/projectdiscovery"
DL = "https://github.com/projectdiscovery"


def _sums(*names: str) -> bytes:
    return "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in names).encode()


def test_update_takes_the_hashes_from_each_release() -> None:
    pages = {
        f"{API}/nuclei/releases/latest": b'{"tag_name":"v3.12.0"}',
        f"{API}/subfinder/releases/latest": b'{"tag_name":"v2.18.0"}',
        f"{API}/nuclei-templates/releases/latest": b'{"tag_name":"v10.6.0"}',
        f"{DL}/nuclei/releases/download/v3.12.0/nuclei_3.12.0_checksums.txt": _sums(
            "nuclei_3.12.0_linux_amd64.zip", "nuclei_3.12.0_linux_arm64.zip"
        ),
        f"{DL}/subfinder/releases/download/v2.18.0/subfinder_2.18.0_checksums.txt": _sums(
            "subfinder_2.18.0_linux_amd64.zip", "subfinder_2.18.0_linux_arm64.zip"
        ),
        f"{DL}/nuclei-templates/releases/download/v10.6.0/nuclei-templates-10.6.0_checksums.txt": (
            _sums("nuclei-templates-10.6.0.tar.gz")
        ),
    }

    lines = tools.lock_lines(pages.__getitem__)

    entries = tools.parse_lock("\n".join(lines))
    assert [(e.tool, e.version, e.arch) for e in entries] == [
        ("nuclei", "3.12.0", "amd64"),
        ("nuclei", "3.12.0", "arm64"),
        ("subfinder", "2.18.0", "amd64"),
        ("subfinder", "2.18.0", "arm64"),
        ("nuclei-templates", "10.6.0", "any"),
    ]
    assert entries[0].sha256 == hashlib.sha256(b"nuclei_3.12.0_linux_amd64.zip").hexdigest()
    assert entries[-1].url.endswith("/archive/refs/tags/v10.6.0.tar.gz")


def test_update_refuses_a_release_without_the_checksum() -> None:
    pages = {
        f"{API}/nuclei/releases/latest": b'{"tag_name":"v3.12.0"}',
        f"{DL}/nuclei/releases/download/v3.12.0/nuclei_3.12.0_checksums.txt": b"",
    }
    with pytest.raises(tools.ToolError, match="no checksum for nuclei_3.12.0_linux_amd64.zip"):
        tools.lock_lines(pages.__getitem__)
