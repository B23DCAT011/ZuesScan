"""A self-hosted interactsh server, for nuclei's out-of-band (OAST) templates (G24).

Some flaws do not show in a response: Log4Shell, a blind SSRF, a blind command injection.
The template sends a payload naming `<id>.<domain>`; a vulnerable target looks that name
up (DNS) or calls it (HTTP, LDAP, SMTP), and the interactsh server that answers for
`<domain>` records it. nuclei asks that server what it received and matches on it.

By default nuclei uses ProjectDiscovery's public servers (oast.pro, oast.fun, ...): every
payload then makes the targets reveal themselves (names, addresses, sometimes data) to a
server outside the engagement. ZuesScan never does that: without a server of your own,
nuclei runs with `-ni` and out-of-band templates do not run. With one:

    ZUES_INTERACTSH_SERVER=https://oast.example.internal   (the server's own domain)
    ZUES_INTERACTSH_TOKEN=...                               (its `-token`, if it has one)

* The public servers are refused, by name; so is an address (payloads are names under the
  server's domain: `<id>.10.0.0.5` resolves nowhere).
* The token never goes on nuclei's command line (visible to every local user, and kept with
  the run as evidence): it is written to a configuration file in the run's own temporary
  directory. Third-party plugins never see it (they get a clean environment, D15).
* Before a scan, the server is asked once (`probe`) whether it answers like an interactsh
  server and accepts the token. nuclei itself carries on silently without one ("interactsh
  client not initialized"), so without this check a dead server would look like targets
  that are not vulnerable.

What the probe cannot see: whether the *targets* can reach the server (their DNS must lead
to it, their firewall must let the callback out). A template that got no callback is
therefore never proof that the flaw is absent, and is worded so (see nuclei.verify).

Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import string
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SERVER_ENV = "ZUES_INTERACTSH_SERVER"
TOKEN_ENV = "ZUES_INTERACTSH_TOKEN"
# ProjectDiscovery's public servers (nuclei's default list) and their old domain.
PUBLIC = ("oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh")
PROBE_TIMEOUT = 10
# Extra seconds nuclei waits for callbacks after its last request (its default is 5): a
# target that queues the lookup, or a slow resolver chain, calls back late.
COOLDOWN = 15


class InteractshError(ValueError):
    """The configured server cannot be used."""


@dataclass(frozen=True)
class Interactsh:
    server: str  # scheme://domain[:port], checked by `server_url`
    token: str | None = field(default=None, repr=False)

    @property
    def domain(self) -> str:
        return urlsplit(self.server).hostname or ""

    def config(self) -> str:
        """nuclei's configuration file for this server (YAML; the token as a JSON string,
        which YAML reads as is)."""
        lines = [f"interactsh-server: {json.dumps(self.server)}"]
        if self.token:
            lines.append(f"interactsh-token: {json.dumps(self.token)}")
        return "\n".join(lines) + "\n"

    def probe(self, timeout: float = PROBE_TIMEOUT) -> str | None:
        """None if the server answers like an interactsh server and takes the token; else
        what is wrong. Asks for the interactions of an id nobody registered: the server
        says it does not know it (HTTP 400), or that the token is wrong (401)."""
        alphabet = string.ascii_lowercase + string.digits
        cid = "".join(secrets.choice(alphabet) for _ in range(33))
        request = urllib.request.Request(
            f"{self.server}/poll?id={cid}&secret={secrets.token_hex(16)}",
            headers={"User-Agent": "zues-scan"},
        )
        if self.token:
            request.add_header("Authorization", self.token)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                code, body = response.status, response.read(512)
        except urllib.error.HTTPError as exc:
            code, body = exc.code, exc.read(512)
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return f"{self.server} is not reachable: {reason}"
        if code == 401:
            if self.token:
                return f"{self.server} refused the token ({TOKEN_ENV})"
            return f"{self.server} needs a token: set {TOKEN_ENV}"
        if code == 400 and b"interactions" in body:
            return None
        return f"{self.server} answered HTTP {code}: not an interactsh server?"


def server_url(value: str) -> str:
    """`value` as `scheme://domain[:port]`, or InteractshError."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InteractshError(
            f"{SERVER_ENV} must be the server's URL, e.g. https://oast.example.internal "
            f"(got {value!r})"
        )
    extra = parts.path not in ("", "/") or parts.query or parts.fragment
    if extra or parts.username or parts.password:
        raise InteractshError(f"{SERVER_ENV}: only scheme://domain[:port], no path or user")
    host = parts.hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise InteractshError(
            f"{SERVER_ENV} needs the server's domain, not an address: payloads are names "
            f"under it (<id>.<domain>), which targets must resolve to the server"
        )
    if any(host == p or host.endswith("." + p) for p in PUBLIC):
        raise InteractshError(
            f"{host} is a public ProjectDiscovery server: targets would call out of the "
            f"engagement. Run interactsh-server in your own network and name it here"
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise InteractshError(f"{SERVER_ENV}: {exc}") from exc
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def from_env(environ: Mapping[str, str] | None = None) -> Interactsh | None:
    """The server the environment names, or None (no out-of-band templates)."""
    env = os.environ if environ is None else environ
    value = (env.get(SERVER_ENV) or "").strip()
    if not value:
        if (env.get(TOKEN_ENV) or "").strip():
            raise InteractshError(f"{TOKEN_ENV} is set but {SERVER_ENV} is not")
        return None
    token = (env.get(TOKEN_ENV) or "").strip() or None
    return Interactsh(server_url(value), token)
