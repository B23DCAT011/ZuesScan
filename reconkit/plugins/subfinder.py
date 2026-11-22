"""subfinder adapter — passive subdomain discovery.

subfinder (ProjectDiscovery) lists the subdomains of a domain from public sources
(certificate transparency logs, DNS datasets, search engines). It sends nothing to
the target itself: it is *passive* recon. Its results are only names; every name still
goes through the scope guard (`Scope.plan_discovered`) before anything is scanned.

`discover()` runs `subfinder -d <domain> -oJ -silent` and reads its JSON lines
(`{"host": "api.example.com", "source": "crtsh", ...}`); `parse_jsonl()` does the
reading as a pure function, tested without the binary. API keys for subfinder's
sources live in subfinder's own provider config, never in ReconKit.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

from reconkit.plugins.base import DiscoveryResult, ScanError
from reconkit.schema import RawOutput

_NAME = re.compile(r"(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]*")


class SubfinderPlugin:
    """Discovery plugin backed by the `subfinder` binary."""

    name = "subfinder"

    def __init__(self, timeout: int = 600, max_minutes: int = 8) -> None:
        self.timeout = timeout  # seconds before ReconKit stops subfinder
        self.max_minutes = max_minutes  # subfinder's own limit, kept below the timeout

    def is_available(self) -> bool:
        return shutil.which("subfinder") is not None

    def version(self) -> str | None:
        try:
            proc = subprocess.run(
                ["subfinder", "-version"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        # It prints e.g. "[INF] Current Version: v2.6.6" (on stderr).
        match = re.search(r"Current Version:\s*v?(\d+(?:\.\d+)+)", proc.stderr + proc.stdout)
        return match.group(1) if match else None

    def command(self, domain: str) -> list[str]:
        return [
            "subfinder",
            "-d",
            domain,
            "-oJ",
            "-silent",
            "-max-time",
            str(self.max_minutes),
            "-disable-update-check",
        ]

    def discover(self, domain: str) -> DiscoveryResult:
        """The names subfinder finds under `domain` (the domain itself not included)."""
        if not self.is_available():
            raise ScanError("subfinder is not installed or not on PATH", plugin=self.name)
        command = self.command(domain)
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(
                f"subfinder timed out after {self.timeout}s for {domain}", plugin=self.name
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise ScanError(
                f"subfinder exited with code {exc.returncode} for {domain}",
                plugin=self.name,
                stderr=(exc.stderr or "").strip() or None,
            ) from exc
        except OSError as exc:
            raise ScanError(f"could not start subfinder: {exc}", plugin=self.name) from exc
        raw = RawOutput(
            plugin=self.name,
            format="subfinder-jsonl",
            command=tuple(command),
            content=proc.stdout,
            stderr=proc.stderr.strip(),
        )
        names, skipped = self.parse_jsonl(proc.stdout, domain)
        notes = (
            [f"ignored {skipped} line(s) of subfinder output it could not read"] if skipped else []
        )
        return DiscoveryResult(names=names, raw=[raw], notes=notes)

    @staticmethod
    def parse_jsonl(text: str, domain: str) -> tuple[list[str], int]:
        """(names under `domain`, unreadable lines). Duplicates and outsiders dropped."""
        suffix = "." + domain.lower().rstrip(".")
        names: dict[str, None] = {}
        skipped = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                host = str(json.loads(line)["host"]).strip().lower().rstrip(".")
            except (json.JSONDecodeError, KeyError, TypeError):
                skipped += 1
                continue
            # A source may hand back wildcard entries or names of other domains.
            if host.endswith(suffix) and _NAME.fullmatch(host):
                names[host] = None
            else:
                skipped += 1
        return sorted(names), skipped
