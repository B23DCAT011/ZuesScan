"""The external tools of the image (nuclei, subfinder, nuclei-templates), pinned.

    python docker/tools.py install --bin DIR --templates DIR [--arch amd64|arm64]
    python docker/tools.py update            # newest releases -> docker/tools.lock

`docker/tools.lock` names each file by URL, version and SHA-256. `install` (run while
the image is built) downloads exactly those files, refuses any whose hash differs, and
unpacks them: from each tool's zip only the binary itself, the templates without the
repository's own files, plus a `.reconkit-version` that ReconKit records with each run.

`update` asks GitHub for the newest release of each tool and takes the hashes from the
release's own checksums file. Review the diff of the lock before committing it: a new
hash for an unchanged version means the file on GitHub is not the one locked before.

Standard library only: it runs in the bare base image.
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

LOCK = Path(__file__).with_name("tools.lock")
REPO = "projectdiscovery"
BINARIES = ("nuclei", "subfinder")
TEMPLATES = "nuclei-templates"
ARCHES = ("amd64", "arm64")
# Repository files that are not templates: not needed to scan, left out of the image.
NOT_TEMPLATES = (".github", ".new-additions", ".review-bot", ".pre-commit-config.yml", ".yamllint")

Fetch = Callable[[str], bytes]


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    tool: str
    version: str
    arch: str  # amd64, arm64, or "any"
    sha256: str
    url: str


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "reconkit-image-build"})
    with urllib.request.urlopen(request, timeout=300) as response:
        data: bytes = response.read()
    return data


def parse_lock(text: str) -> list[Entry]:
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 5:
            raise ToolError(f"tools.lock line {number}: expected 5 fields, got {len(fields)}")
        tool, version, arch, sha256, url = fields
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ToolError(f"tools.lock line {number}: bad sha256")
        if not url.startswith("https://"):
            raise ToolError(f"tools.lock line {number}: the URL must be https")
        entries.append(Entry(tool, version, arch, sha256, url))
    return entries


def machine_arch() -> str:
    """The Docker name of this machine's architecture (TARGETARCH while building)."""
    named = os.environ.get("TARGETARCH")
    if named:
        return named
    machine = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine, machine
    )


def download(entry: Entry, get: Fetch = fetch) -> bytes:
    data = get(entry.url)
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry.sha256:
        raise ToolError(
            f"{entry.tool} {entry.version}: SHA-256 {digest} differs from the locked "
            f"{entry.sha256} ({entry.url}); refusing it"
        )
    return data


def install_binary(entry: Entry, data: bytes, bin_dir: Path) -> Path:
    """Only the binary named like the tool comes out of the zip, whatever else it holds."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        try:
            binary = archive.read(entry.tool)
        except KeyError:
            raise ToolError(f"{entry.url} has no file named {entry.tool!r}") from None
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / entry.tool
    target.write_bytes(binary)
    target.chmod(0o755)
    return target


def install_templates(entry: Entry, data: bytes, dest: Path) -> Path:
    """Unpack the templates into `dest` (replaced), safely, with their version."""
    with tempfile.TemporaryDirectory() as work:
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
        (root / ".reconkit-version").write_text(entry.version + "\n", encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(root), str(dest))
    return dest


def install(
    entries: list[Entry], bin_dir: Path, templates: Path, arch: str, get: Fetch = fetch
) -> list[str]:
    chosen = [e for e in entries if e.arch in (arch, "any")]
    missing = [t for t in (*BINARIES, TEMPLATES) if t not in {e.tool for e in chosen}]
    if missing:
        raise ToolError(f"tools.lock has nothing for {', '.join(missing)} on {arch}")
    done = []
    for entry in chosen:
        data = download(entry, get)
        if entry.tool == TEMPLATES:
            install_templates(entry, data, templates)
        else:
            install_binary(entry, data, bin_dir)
        done.append(f"{entry.tool} {entry.version} ({entry.arch}) sha256 ok")
    return done


# --- update -----------------------------------------------------------------------------------


def checksums(text: str) -> dict[str, str]:
    """`<sha256>  <file name>` lines -> {file name: sha256}."""
    sums = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and len(fields[0]) == 64:
            sums[fields[1].lstrip("*")] = fields[0].lower()
    return sums


def latest(tool: str, get: Fetch = fetch) -> str:
    release = json.loads(get(f"https://api.github.com/repos/{REPO}/{tool}/releases/latest"))
    tag = str(release["tag_name"])
    return tag.lstrip("v")


def lock_lines(get: Fetch = fetch) -> list[str]:
    lines = []
    for tool in BINARIES:
        version = latest(tool, get)
        base = f"https://github.com/{REPO}/{tool}/releases/download/v{version}"
        sums = checksums(get(f"{base}/{tool}_{version}_checksums.txt").decode())
        for arch in ARCHES:
            name = f"{tool}_{version}_linux_{arch}.zip"
            if name not in sums:
                raise ToolError(f"{tool} {version}: no checksum for {name}")
            lines.append(f"{tool} {version} {arch} {sums[name]} {base}/{name}")
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
# External tools of the image, pinned by version and SHA-256 (see docker/tools.py).
# Hashes come from each release's own checksums file. Regenerate with:
#     python docker/tools.py update
# tool version arch sha256 url
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    install_cmd = sub.add_parser("install")
    install_cmd.add_argument("--bin", required=True, type=Path)
    install_cmd.add_argument("--templates", required=True, type=Path)
    install_cmd.add_argument("--arch", default=None)
    install_cmd.add_argument("--lock", type=Path, default=LOCK)
    update_cmd = sub.add_parser("update")
    update_cmd.add_argument("--lock", type=Path, default=LOCK)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            entries = parse_lock(args.lock.read_text(encoding="utf-8"))
            for line in install(entries, args.bin, args.templates, args.arch or machine_arch()):
                print(line)
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
