"""dnsx adapter — subdomains guessed from a wordlist and confirmed in DNS.

subfinder only knows the names public sources have seen (certificate transparency logs,
DNS datasets). A name that never got a public certificate — `vpn.`, `intranet.`, an old
staging server — is only found by asking DNS itself: dnsx (ProjectDiscovery) asks for
`<word>.<domain>` for every word of a wordlist and keeps the names that resolve.

Its queries reach the domain's own DNS servers (through the resolvers), so it is not
passive: its activity is `scan`, and its rate is capped (the profile's `check_rate`).

Wildcard DNS (`*.example.com` answering for every name) would make every word "exist".
Two random names are asked as well; a name that answers with nothing but the wildcard's
addresses is dropped here, and the scope guard checks every name again before anything
is scanned (`Scope.plan_discovered`).

One level deeper: names often nest (`api.dev.example.com`, `db.corp.example.com`), and a
name that exists is the best hint that more live under it. After the first pass, the
same wordlist is tried under up to `recurse` (10) of the names found directly under the
domain, with two random names under each to recognise a wildcard there too. One level
only: each level multiplies the queries by the wordlist's size.

The wordlist is ZuesScan's own (`zues_scan/data/subdomains.txt`, a few hundred names
common in companies), or any file given (`--dns-wordlist`, `dns_wordlist` in the service).
The resolvers are the system's, the same the scope guard resolves with, so internal
names resolve inside an internal network: `/etc/resolv.conf`, or on Windows the DNS
servers Windows itself uses (`GetNetworkParams`). Only when the system names none does
dnsx fall back to its own public resolvers (and the run says so).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from zues_scan import tools
from zues_scan.plugins.base import DiscoveryResult, ScanError
from zues_scan.schema import RawOutput
from zues_scan.scope import Activity

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_WORD = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_NAME = re.compile(r"(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]*")
PROBE = "zues-wildcard-"  # random names asked to recognise wildcard DNS
MAX_WORDS = 50_000  # a bigger list would not finish within the time budget anyway
RECURSE = 10  # names found under the domain that the wordlist is tried under again
BUNDLED = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"


class DnsxPlugin:
    """Discovery plugin backed by the `dnsx` binary."""

    name = "dnsx"
    activity = Activity.SCAN  # queries reach the domain's own DNS servers

    def __init__(
        self,
        wordlist: str | None = None,
        rate: int = 100,
        timeout: int = 600,
        resolv_conf: str | None = None,
        recurse: int = RECURSE,
    ) -> None:
        self.wordlist = wordlist  # None: the bundled list
        self.rate = max(1, rate)  # DNS queries per second, at most
        self.timeout = timeout  # seconds before ZuesScan stops dnsx (both passes)
        self.resolv_conf = resolv_conf  # None: the system's (Windows: its DNS servers)
        self.recurse = max(0, recurse)  # names looked under one level deeper; 0: none

    def is_available(self) -> bool:
        return tools.which("dnsx") is not None

    def version(self) -> str | None:
        try:
            # In a fresh home: dnsx writes a default config there on first use.
            with tempfile.TemporaryDirectory(prefix="zues-dnsx-") as home:
                proc = subprocess.run(
                    [tools.resolve("dnsx"), "-version", "-duc"],
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                    env=_env(home),
                )
        except (OSError, subprocess.SubprocessError):
            return None
        # It prints e.g. "[INF] Current Version: 1.3.1" (on stderr).
        match = re.search(r"Current Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        return match.group(1) if match else None

    # --- what to ask ---------------------------------------------------------------------------

    def words(self) -> tuple[list[str], str]:
        """(the words to try, where they come from). Bad lines are skipped, not fatal."""
        if self.wordlist:
            try:
                text = Path(self.wordlist).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ScanError(
                    f"cannot read the DNS wordlist {self.wordlist}: {exc}", plugin=self.name
                ) from exc
            source = self.wordlist
        else:
            text = BUNDLED.read_text(encoding="utf-8")
            source = "ZuesScan's own list"
        return parse_wordlist(text), source

    def resolvers(self) -> list[str]:
        """The system's IPv4 resolvers, if it names any (else dnsx uses its own)."""
        if self.resolv_conf is None and sys.platform == "win32":
            return windows_resolvers()
        try:
            path = Path(self.resolv_conf or "/etc/resolv.conf")
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return parse_resolv_conf(text)

    def command(self, names_file: str, resolvers: list[str]) -> list[str]:
        command = [
            tools.resolve("dnsx"),
            "-l",
            names_file,
            "-json",
            "-silent",
            "-nc",
            "-duc",
            "-a",
            "-aaaa",
            "-rl",
            str(self.rate),
            "-t",
            str(min(self.rate, 50)),
            "-retry",
            "2",
        ]
        if resolvers:
            command += ["-r", ",".join(resolvers)]
        return command

    # --- running it ----------------------------------------------------------------------------

    def discover(self, domain: str) -> DiscoveryResult:
        """The names under `domain` that resolve (the domain itself not included)."""
        if not self.is_available():
            raise ScanError("dnsx is not installed or not on PATH", plugin=self.name)
        domain = domain.lower().rstrip(".")
        words, source = self.words()
        if not words:
            raise ScanError(f"the DNS wordlist ({source}) holds no usable word", plugin=self.name)
        notes = []
        if len(words) == MAX_WORDS:
            notes.append(f"only the first {MAX_WORDS} words of {source} were tried")
        deadline = time.monotonic() + self.timeout
        resolvers = self.resolvers()
        if not resolvers:  # internal names will not be found: say so
            notes.append(
                "the system names no DNS server: dnsx asked public resolvers, "
                "names only internal DNS knows are not found"
            )
        stdout, raw, stopped = self._pass([domain], words, resolvers, self.timeout)
        names, wildcard, skipped = parse_jsonl(stdout, domain)
        notes.insert(0, f"tried {len(words)} name(s) from {source}; {len(names)} found")
        if wildcard:
            notes.append(
                f"wildcard DNS under {domain} (any name answers): {wildcard} name(s) "
                "answering with nothing but the wildcard's addresses dropped"
            )
        raws = [raw]
        # One level deeper, under the names found directly under the domain.
        depth = domain.count(".") + 1
        parents = [n for n in names if n.count(".") == depth][: self.recurse]
        left = int(deadline - time.monotonic())
        if parents and not stopped and left >= 1:
            stdout, raw, stopped = self._pass(parents, words, resolvers, left)
            raws.append(raw)
            deeper: list[str] = []
            for parent in parents:
                found, dropped, _ = parse_jsonl(stdout, parent)
                deeper += [n for n in found if n not in names]
                if dropped:
                    notes.append(
                        f"wildcard DNS under {parent}: {dropped} name(s) answering with "
                        "nothing but the wildcard's addresses dropped"
                    )
            shown = ", ".join(parents[:3]) + (
                f" and {len(parents) - 3} more" if len(parents) > 3 else ""
            )
            notes.append(
                f"one level deeper under {len(parents)} name(s) ({shown}): {len(deeper)} more found"
            )
            names = sorted({*names, *deeper})
        elif parents and not stopped:
            stopped = True
        if stopped:
            notes.append(
                f"stopped after {self.timeout}s: only part of the wordlist was tried "
                "(a smaller list or a higher check_rate finishes sooner)"
            )
        if skipped:
            notes.append(f"ignored {skipped} line(s) of dnsx output it could not read")
        return DiscoveryResult(names=names, raw=raws, notes=notes)

    def _pass(
        self, parents: list[str], words: list[str], resolvers: list[str], timeout: int
    ) -> tuple[str, RawOutput, bool]:
        """One dnsx run: every word under every parent, and two random names under each
        (wildcards). Its output, kept as raw output, and whether it ran out of time."""
        candidates = [f"{word}.{parent}" for parent in parents for word in words]
        candidates += [f"{PROBE}{secrets.token_hex(6)}.{p}" for p in parents for _ in range(2)]
        stopped = False
        with tempfile.TemporaryDirectory(prefix="zues-dnsx-") as home:
            names_file = os.path.join(home, "names.txt")
            Path(names_file).write_text("\n".join(candidates) + "\n", encoding="utf-8")
            command = self.command(names_file, resolvers)
            try:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=True,
                    env=_env(home),
                )
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                # What it confirmed before the time ran out is still true: keep it.
                stdout, stderr, stopped = _text(exc.stdout), _text(exc.stderr), True
            except subprocess.CalledProcessError as exc:
                raise ScanError(
                    f"dnsx exited with code {exc.returncode} for {', '.join(parents[:3])}",
                    plugin=self.name,
                    stderr=(exc.stderr or "").strip() or None,
                ) from exc
            except OSError as exc:
                raise ScanError(f"could not start dnsx: {exc}", plugin=self.name) from exc
        raw = RawOutput(
            plugin=self.name,
            format="dnsx-jsonl",
            command=tuple(command),
            content=stdout,
            stderr=stderr.strip(),
        )
        return stdout, raw, stopped


def parse_wordlist(text: str) -> list[str]:
    """Words of a wordlist, lowercased, each once: blank, `#` and invalid lines skipped."""
    words: dict[str, None] = {}
    for line in text.splitlines():
        word = line.strip().lower().strip(".")
        if word and not word.startswith("#") and _WORD.fullmatch(word):
            words[word] = None
            if len(words) == MAX_WORDS:
                break
    return list(words)


MAX_RESOLVERS = 16


def windows_resolvers() -> list[str]:
    """The IPv4 DNS servers Windows resolves with (GetNetworkParams), in order; [] when
    it cannot tell. (Its IPv6 list is mostly the obsolete fec0::/10 placeholders.)"""
    return _ipv4_only(_network_params_dns())


def _ipv4_only(found: list[str]) -> list[str]:
    kept: dict[str, None] = {}
    for text in found:
        try:
            if isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address):
                kept[text] = None
        except ValueError:
            continue
    return list(kept)[:MAX_RESOLVERS]


def _network_params_dns() -> list[str]:
    if sys.platform != "win32":
        return []
    import ctypes
    from ctypes import wintypes

    class IpAddrString(ctypes.Structure):
        pass

    IpAddrString._fields_ = [
        ("Next", ctypes.POINTER(IpAddrString)),
        ("IpAddress", ctypes.c_char * 16),
        ("IpMask", ctypes.c_char * 16),
        ("Context", wintypes.DWORD),
    ]

    class FixedInfo(ctypes.Structure):  # FIXED_INFO of iphlpapi.h
        _fields_ = [
            ("HostName", ctypes.c_char * 132),
            ("DomainName", ctypes.c_char * 132),
            ("CurrentDnsServer", ctypes.POINTER(IpAddrString)),
            ("DnsServerList", IpAddrString),
            ("NodeType", wintypes.UINT),
            ("ScopeId", ctypes.c_char * 260),
            ("EnableRouting", wintypes.UINT),
            ("EnableProxy", wintypes.UINT),
            ("EnableDns", wintypes.UINT),
        ]

    try:
        get = ctypes.windll.iphlpapi.GetNetworkParams
        size = wintypes.ULONG(0)
        get(None, ctypes.byref(size))  # ERROR_BUFFER_OVERFLOW: the size it needs
        buffer = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(FixedInfo)))
        if get(buffer, ctypes.byref(size)) != 0:
            return []
        info = FixedInfo.from_buffer(buffer)
        found: list[str] = []
        entry = ctypes.pointer(info.DnsServerList)
        while entry and len(found) < MAX_RESOLVERS:
            found.append(entry.contents.IpAddress.decode("ascii", "replace"))
            entry = entry.contents.Next
        return found
    except (OSError, AttributeError, ValueError):
        return []


def parse_resolv_conf(text: str) -> list[str]:
    """The IPv4 `nameserver` entries of a resolv.conf, in order."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            try:
                if isinstance(ipaddress.ip_address(fields[1]), ipaddress.IPv4Address):
                    found.append(fields[1])
            except ValueError:
                continue
    return found


def parse_jsonl(text: str, domain: str) -> tuple[list[str], int, int]:
    """(names under `domain`, names dropped as wildcard answers, unreadable lines)."""
    suffix = "." + domain.lower().rstrip(".")
    answers: dict[str, frozenset[str]] = {}
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            host = str(record["host"]).strip().lower().rstrip(".")
            addresses = frozenset(
                str(a) for a in (record.get("a") or []) + (record.get("aaaa") or [])
            )
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
            skipped += 1
            continue
        if host.endswith(suffix) and _NAME.fullmatch(host):
            answers[host] = answers.get(host, frozenset()) | addresses
        else:
            skipped += 1
    wildcard_addresses: frozenset[str] = frozenset()
    for host, addresses in answers.items():
        if host.startswith(PROBE):
            wildcard_addresses |= addresses
    names, wildcard = [], 0
    for host, addresses in sorted(answers.items()):
        if host.startswith(PROBE):
            continue
        if wildcard_addresses and addresses and addresses <= wildcard_addresses:
            wildcard += 1
            continue
        names.append(host)
    return names, wildcard, skipped


def _env(home: str) -> dict[str, str]:
    return {**os.environ, "HOME": home, "USERPROFILE": home}


def _text(output: bytes | str | None) -> str:
    if output is None:
        return ""
    return output.decode("utf-8", "replace") if isinstance(output, bytes) else output
