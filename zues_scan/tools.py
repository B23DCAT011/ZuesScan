"""The external tools ZuesScan can install itself: nuclei, subfinder, dnsx, nuclei-templates.

    zues tools list | install [TOOL...] | verify | path
    python -m zues_scan.tools update            # newest releases -> zues_scan/data/tools.lock

Only single-binary, MIT-licensed tools are installed this way, into the user's own data
directory (no administrator rights): `~/.local/share/zues/tools` on Linux,
`~/Library/Application Support/zues/tools` on macOS, `%LOCALAPPDATA%\\zues\\tools`
on Windows, or `$ZUES_TOOLS_DIR`. System packages (nmap, ssh) are left to the system's
package manager: `zues doctor` prints the command.

`zues_scan/data/tools.lock` names each release file by platform, version, URL and SHA-256
(taken from the release's own checksums file). `install` downloads exactly those files and
refuses any other hash, takes only the binary out of each zip, unpacks the templates with
tarfile's "data" filter, and records the SHA-256 of what it wrote, which `verify` checks
again later. The Docker image is built with the same file and the same code.

Plugins find a tool here first, then on PATH (`which`, `resolve`).

Standard library only, and no ZuesScan imports: the image build runs this file as a
script before ZuesScan itself is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

LOCK = Path(__file__).with_name("data") / "tools.lock"
REPO = "projectdiscovery"
BINARIES = ("nuclei", "subfinder", "dnsx")
TEMPLATES = "nuclei-templates"
TOOLS = (*BINARIES, TEMPLATES)
# Release file naming of ProjectDiscovery, per platform this module supports.
PLATFORMS = {
    "linux-amd64": "linux_amd64",
    "linux-arm64": "linux_arm64",
    "darwin-amd64": "macOS_amd64",
    "darwin-arm64": "macOS_arm64",
    "windows-amd64": "windows_amd64",
}
MANIFEST = "installed.json"
TEMPLATES_VERSION = ".zues-version"
NOT_TEMPLATES = (".github", ".new-additions", ".review-bot", ".pre-commit-config.yml", ".yamllint")

Fetch = Callable[[str], bytes]


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    tool: str
    version: str
    platform: str  # a PLATFORMS key, or "any"
    sha256: str
    url: str


# --- where and which ------------------------------------------------------------------------------


def current_platform() -> str:
    """This machine as a PLATFORMS key (TARGETARCH wins while building an image)."""
    system = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(
        sys.platform, sys.platform
    )
    arch = os.environ.get("TARGETARCH") or {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower(), platform.machine().lower())
    return f"{system}-{arch}"


def default_root() -> Path:
    named = os.environ.get("ZUES_TOOLS_DIR")
    if named:
        return Path(named)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "zues" / "tools"


def _exe(name: str) -> str:
    return f"{name}.exe" if sys.platform == "win32" else name


def managed(name: str, root: Path | None = None) -> str | None:
    """A tool installed by `zues tools install`, if it is there."""
    path = (root or default_root()) / "bin" / _exe(name)
    return str(path) if path.is_file() else None


def managed_templates(root: Path | None = None) -> str | None:
    path = (root or default_root()) / TEMPLATES
    return str(path) if path.is_dir() else None


def _windows_install(name: str) -> str | None:
    """Where the official Windows installers put nmap: found even before a terminal
    restart makes the installer's PATH change visible."""
    if sys.platform != "win32" or name != "nmap":
        return None
    for root in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if root and Path(root, "Nmap", "nmap.exe").is_file():
            return str(Path(root, "Nmap", "nmap.exe"))
    return None


def which(name: str) -> str | None:
    """The program a plugin will run: ZuesScan's own copy, else PATH, else a known place."""
    return managed(name) or shutil.which(name) or _windows_install(name)


def resolve(name: str) -> str:
    """What to put first in a command: a full path where PATH would not find it."""
    path = managed(name)
    if path:
        return path
    if shutil.which(name):
        return name
    return _windows_install(name) or name


# --- the lock -------------------------------------------------------------------------------------


def parse_lock(text: str) -> list[Entry]:
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 5:
            raise ToolError(f"tools.lock line {number}: expected 5 fields, got {len(fields)}")
        tool, version, where, sha256, url = fields
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ToolError(f"tools.lock line {number}: bad sha256")
        if not url.startswith("https://"):
            raise ToolError(f"tools.lock line {number}: the URL must be https")
        if where != "any" and where not in PLATFORMS:
            raise ToolError(f"tools.lock line {number}: unknown platform {where!r}")
        entries.append(Entry(tool, version, where, sha256, url))
    return entries


def read_lock(path: Path = LOCK) -> list[Entry]:
    return parse_lock(path.read_text(encoding="utf-8"))


def for_platform(entries: list[Entry], where: str) -> dict[str, Entry]:
    return {e.tool: e for e in entries if e.platform in (where, "any")}


# --- installing -----------------------------------------------------------------------------------


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "zues-tools"})
    with urllib.request.urlopen(request, timeout=300) as response:
        data: bytes = response.read()
    return data


def download(entry: Entry, get: Fetch | None = None) -> bytes:
    data = (get or fetch)(entry.url)
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry.sha256:
        raise ToolError(
            f"{entry.tool} {entry.version}: SHA-256 {digest} differs from the locked "
            f"{entry.sha256} ({entry.url}); refusing it"
        )
    return data


def install_binary(entry: Entry, data: bytes, bin_dir: Path) -> Path:
    """Only the binary named like the tool comes out of the zip, whatever else it holds."""
    member = f"{entry.tool}.exe" if entry.platform.startswith("windows") else entry.tool
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        try:
            binary = archive.read(member)
        except KeyError:
            raise ToolError(f"{entry.url} has no file named {member!r}") from None
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / member
    partial = target.with_name(target.name + ".partial")
    partial.write_bytes(binary)
    partial.chmod(0o755)
    partial.replace(target)
    return target


def install_templates(entry: Entry, data: bytes, dest: Path) -> Path:
    """Unpack the templates into `dest` (replaced), safely, with their version."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as work:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            # "data": no absolute paths, no "..", no links out, no devices.
            archive.extractall(work, filter="data")
        tops = [p for p in Path(work).iterdir() if p.is_dir()]
        if len(tops) != 1:
            raise ToolError(f"{entry.url}: expected one top directory, got {len(tops)}")
        root = tops[0]
        for name in NOT_TEMPLATES:
            path = root / name
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        for doc in root.glob("*.md"):
            doc.unlink()
        (root / TEMPLATES_VERSION).write_text(entry.version + "\n", encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(root), str(dest))
    return dest


def tree_digest(folder: Path) -> str:
    """One SHA-256 over every file of a directory (path and content), in a fixed order."""
    digest = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        digest.update(path.relative_to(folder).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(
    entries: list[Entry],
    root: Path,
    where: str,
    tools: tuple[str, ...] = TOOLS,
    get: Fetch | None = None,
    bin_dir: Path | None = None,
    templates_dir: Path | None = None,
) -> list[str]:
    """Install `tools` for platform `where` under `root`; one line per tool done."""
    available = for_platform(entries, where)
    missing = [t for t in tools if t not in available]
    if missing:
        raise ToolError(f"the lock has nothing for {', '.join(missing)} on {where}")
    bin_dir = bin_dir or root / "bin"
    templates_dir = templates_dir or root / TEMPLATES
    manifest = _read_manifest(root)
    done = []
    for tool in tools:
        entry = available[tool]
        data = download(entry, get)
        if tool == TEMPLATES:
            path = install_templates(entry, data, templates_dir)
            digest = tree_digest(path)
        else:
            path = install_binary(entry, data, bin_dir)
            digest = file_digest(path)
        manifest[tool] = {"version": entry.version, "path": str(path), "sha256": digest}
        done.append(f"{tool} {entry.version} ({entry.platform}): download checked, {path}")
    _write_manifest(root, manifest)
    return done


def _read_manifest(root: Path) -> dict[str, dict[str, str]]:
    try:
        data = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_manifest(root: Path, manifest: dict[str, dict[str, str]]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (root / MANIFEST).write_text(text, encoding="utf-8")


def installed(root: Path) -> dict[str, dict[str, str]]:
    return _read_manifest(root)


def verify(root: Path) -> list[str]:
    """Problems with what `install` put under `root` (empty: all intact)."""
    problems = []
    for tool, record in sorted(_read_manifest(root).items()):
        path = Path(record["path"])
        if not path.exists():
            problems.append(f"{tool}: {path} is gone")
            continue
        now = tree_digest(path) if path.is_dir() else file_digest(path)
        if now != record["sha256"]:
            problems.append(f"{tool}: {path} changed since it was installed")
    return problems


# --- updating the lock ----------------------------------------------------------------------------


def checksums(text: str) -> dict[str, str]:
    """`<sha256>  <file name>` lines -> {file name: sha256}."""
    sums = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and len(fields[0]) == 64:
            sums[fields[1].lstrip("*")] = fields[0].lower()
    return sums


def release_checksums(tool: str, version: str, base: str, get: Fetch) -> dict[str, str]:
    """The checksums file of a release: `<tool>_<version>_checksums.txt` for most tools,
    `<tool>-checksums.txt` for some (naabu)."""
    for name in (f"{tool}_{version}_checksums.txt", f"{tool}-checksums.txt"):
        try:
            return checksums(get(f"{base}/{name}").decode())
        except OSError:
            continue
    raise ToolError(f"{tool} {version}: no checksums file in the release")


def latest(tool: str, get: Fetch | None = None) -> str:
    get = get or fetch
    release = json.loads(get(f"https://api.github.com/repos/{REPO}/{tool}/releases/latest"))
    return str(release["tag_name"]).lstrip("v")


def lock_lines(get: Fetch | None = None) -> list[str]:
    get = get or fetch
    lines = []
    for tool in BINARIES:
        version = latest(tool, get)
        base = f"https://github.com/{REPO}/{tool}/releases/download/v{version}"
        sums = release_checksums(tool, version, base, get)
        for where, suffix in PLATFORMS.items():
            name = f"{tool}_{version}_{suffix}.zip"
            if name not in sums:
                raise ToolError(f"{tool} {version}: no checksum for {name}")
            lines.append(f"{tool} {version} {where} {sums[name]} {base}/{name}")
    version = latest(TEMPLATES, get)
    base = f"https://github.com/{REPO}/{TEMPLATES}/releases/download/v{version}"
    sums = checksums(get(f"{base}/{TEMPLATES}-{version}_checksums.txt").decode())
    name = f"{TEMPLATES}-{version}.tar.gz"
    if name not in sums:
        raise ToolError(f"{TEMPLATES} {version}: no checksum for {name}")
    archive = f"https://github.com/{REPO}/{TEMPLATES}/archive/refs/tags/v{version}.tar.gz"
    lines.append(f"{TEMPLATES} {version} any {sums[name]} {archive}")
    return lines


HEADER = """\
# External tools ZuesScan installs (zues tools install, and the Docker image), pinned
# by version and SHA-256 taken from each release's own checksums file. Regenerate with
#     python -m zues_scan.tools update
# and review the diff: a new hash for an unchanged version means the file was replaced.
# tool version platform sha256 url
"""


def main(argv: list[str] | None = None) -> int:
    """For the image build and for maintainers (users: `zues tools`)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    install_cmd = sub.add_parser("install")
    install_cmd.add_argument("--lock", type=Path, default=LOCK)
    install_cmd.add_argument("--root", type=Path, default=None)
    install_cmd.add_argument("--bin", type=Path, default=None)
    install_cmd.add_argument("--templates", type=Path, default=None)
    install_cmd.add_argument("--platform", default=None)
    update_cmd = sub.add_parser("update")
    update_cmd.add_argument("--lock", type=Path, default=LOCK)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            root = args.root or (args.bin.parent if args.bin else default_root())
            done = install(
                read_lock(args.lock),
                root,
                args.platform or current_platform(),
                bin_dir=args.bin,
                templates_dir=args.templates,
            )
            print("\n".join(done))
        else:
            text = HEADER + "\n".join(lock_lines()) + "\n"
            args.lock.write_text(text, encoding="utf-8", newline="\n")
            print(f"{args.lock} updated; review the diff before committing it")
    except (ToolError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
