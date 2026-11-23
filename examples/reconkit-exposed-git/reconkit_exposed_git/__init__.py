"""exposed-git — an example ReconKit check plugin, packaged on its own.

For every web service the port scan found, it asks for `/.git/HEAD` at the address the
scope guard approved. A web server that answers with a Git reference publishes its
repository: source code, often secrets in the history (CWE-538).

What makes it a ReconKit plugin, and nothing more:

* a class with `name`, `activity`, `is_available()`, `version()` and `check()`
  (the `CheckPlugin` protocol of reconkit.plugins.base);
* a `PluginSpec` named by an entry point in pyproject.toml, group `reconkit.plugins`.

`activity = Activity.ACTIVE`: it probes for a known weakness, so a scope must allow
`@activity active` before it runs.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from reconkit.plugins.base import ScanError, ScanResult
from reconkit.plugins.nuclei import web_url
from reconkit.plugins.registry import PluginContext, PluginSpec
from reconkit.schema import Asset, Confidence, Finding, RawOutput, ScanTarget, Severity
from reconkit.scope import Activity

__version__ = "0.1.0"
TIMEOUT = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None  # a redirect could lead to an address the scope never approved


class ExposedGitCheck:
    name = "exposed-git"
    activity = Activity.ACTIVE

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def is_available(self) -> bool:
        return True  # Python only: no program to install

    def version(self) -> str | None:
        return __version__

    def check(self, plan: ScanTarget, assets: list[Asset]) -> ScanResult:
        found: dict[str, Asset] = {}
        log: list[str] = []
        for asset in assets:
            for service in asset.services:
                url = web_url(asset.ip or "", service) if asset.ip else None
                if url is None:
                    continue
                probe = f"{url}/.git/HEAD"
                status, body = self._get(probe)
                log.append(f"GET {probe} -> {status} {body[:60]!r}")
                if status == 200 and body.startswith("ref: refs/"):
                    finding = Finding(
                        asset=asset.host,
                        ip=asset.ip,
                        title="Git repository exposed over HTTP",
                        severity=Severity.HIGH,
                        service=service,
                        rule_id="exposed-git",
                        confidence=Confidence.CONFIRMED,
                        cwe=("CWE-538",),
                        description="The web server serves its .git directory: anyone can "
                        "download the source code and its history, secrets included.",
                        evidence=f"GET {probe} returned {body.strip()[:80]!r}",
                    )
                    found.setdefault(asset.ip or "", Asset(host=asset.host, ip=asset.ip))
                    found[asset.ip or ""].findings.append(finding)
        raw = RawOutput(self.name, "text", (self.name, *plan.addresses), "\n".join(log) + "\n")
        return ScanResult(assets=list(found.values()), raw=[raw] if log else [])

    def _get(self, url: str) -> tuple[int, str]:
        request = urllib.request.Request(url, headers={"User-Agent": "reconkit-exposed-git"})
        try:
            with self._opener.open(request, timeout=TIMEOUT) as response:
                return response.status, response.read(256).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # A web service that stops answering is not a finding, nor a reason to
            # throw the whole scan away: it is noted in the raw output.
            if isinstance(exc, ConnectionRefusedError):
                return 0, "connection refused"
            if isinstance(exc, urllib.error.URLError) and not isinstance(exc.reason, OSError):
                raise ScanError(f"{url}: {exc.reason}", plugin=ExposedGitCheck.name) from exc
            return 0, f"no answer: {exc}"


def _build(ctx: PluginContext) -> ExposedGitCheck:
    return ExposedGitCheck()


PLUGIN = PluginSpec(
    name="exposed-git",
    kind="check",
    activity=ExposedGitCheck.activity,
    summary=".git directories served over HTTP (example plugin package)",
    factory=_build,
)
