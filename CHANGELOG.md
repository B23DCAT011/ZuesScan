# Changelog

All notable changes, per release. The format follows [Keep a Changelog](https://keepachangelog.com),
versions follow [Semantic Versioning](https://semver.org). The release workflow publishes the
section of a version as its release notes, so every tag needs one.

## [Unreleased]

## [0.2.0] - 2026-11-24

The first release meant to be installed by others: a service with a web dashboard where
admins set scopes, targets, tools and tokens (no file to edit: three commands to install),
a hardened image, real nuclei / subfinder / dnsx / naabu / httpx integration, plugins, AI
agents over MCP, and a vulnerable lab to try it on.

**Renamed: ReconKit is now ZuesScan.** Package `zues-scan` (import `zues_scan`), command
`zues`, environment variables `ZUES_*` (were `RECONKIT_*`), image `ghcr.io/<owner>/zues-scan`,
plugin entry point group `zues_scan.plugins`, default database `zues.db`. Data written before
the rename keeps working: databases (the `reconkit_version` column keeps its name), CVE data
files in the `reconkit-cve` format, templates with a `.reconkit-version` file, and
`reconkit-*.db` backups (rotated too).

### Added
- Install without editing a file: `--config` is optional for `web`, `worker`, `scheduler`,
  `enqueue` and `user` ($ZUES_CONFIG, else settings from ZUES_DB, ZUES_REDIS_URL,
  ZUES_QUEUE, ZUES_CVE_CACHE, ZUES_WEBHOOK, ZUES_NOTIFY_MIN_PRIORITY, with targets, scopes
  and tokens from the dashboard). compose.yaml no longer needs deploy/service.toml:
  `docker compose up -d`, `docker compose exec web zues user add NAME --role admin`, then
  everything in Settings. The lab keeps its file through ZUES_CONFIG.
- Dashboard **Settings** page (admins): targets, scopes and tokens in tables (service.toml's
  marked read-only), a scope editor with a template and the directives' syntax, a target
  form (scope, profile, schedule, plugins by kind with their activity and whether the
  server has them), token creation shown once and revocation. Errors keep the form as it
  was. The audit view and `zues audit` say what a `config` event did.
- Settings in the dashboard's API, for a new `admin` role (an admin is an operator too):
  scopes (the text of a scope file), targets (address, scope, profile, schedule, scanners,
  checks, discoverers) and tokens, kept in the database (schema 14) next to service.toml,
  which stays read-only and wins a name both define. Checked before saving as a scan
  would: the scope parses, the target is inside it, plugins exist and stay within its
  `@activity`; no server file paths from the dashboard; a used scope or the last admin
  cannot be deleted. Every change is a `config` event in the hash-chained audit trail;
  the services see changes without a restart. `zues user add NAME --role admin` makes the
  first admin (and recovers access). `Scope.from_text`, `ScanSpec.scope_text`.
- httpx check plugin (`--check httpx`): what each web service is — URL, status, title,
  Server header, technologies (Wappalyzer) — fetched with a plain GET of `/`, by address,
  redirects not followed, rate from `check_rate`. Kept on the service (`Service.web`,
  database schema 13), shown by `zues scan`, the HTML map, the API and MCP. Technologies
  with a version and a known CPE name (`TECH_NAMES`) go to the CVE stage as software on
  that port; the same CVE inferred by nmap and httpx is one finding, both observations in
  its evidence. The lab targets run httpx with nuclei, and CI checks it.
- naabu scanner plugin (`--scanner naabu`): nmap finds the live hosts (`-sn`; naabu cannot
  without root), naabu finds their open ports with a connect scan at a fixed rate
  (`max_rate`, default 1000/s; no raw sockets), nmap identifies the services on those ports
  only (names and versions for the CVE stage). Live hosts with nothing open are kept, as
  with nmap; out of time or a failed service detection keeps the ports and marks the run
  partial. Measured on the lab: same results as nmap, slower on a fast LAN (see README).
  `NmapPlugin(ping_only=True)` and `ScanProfile.ping_args()` for host discovery only.
- dnsx discovery plugin (`--discoverer dnsx`): subdomains guessed from a wordlist and
  confirmed in DNS, for names public sources never saw (`vpn.`, `intranet.`). Activity
  `scan` (it queries the domain's own DNS servers), rate capped by the profile's
  `check_rate`, wildcard DNS recognised with two random names, the system's resolvers.
  ZuesScan's own wordlist (~370 common names) or `--dns-wordlist` / `dns_wordlist`.
  Installed by `zues tools install` and in the Docker image (pinned in tools.lock).
- `zues mcp`: ZuesScan as tools for AI agents over the Model Context Protocol (stdio),
  as a client of the web API. Queueing a scan, claiming a fix and reopening a finding need
  the user's confirmation through the MCP client; risk acceptance is not offered to agents;
  only configured targets can be scanned; scan data is cleaned and marked as untrusted.
  Install with `zues-scan[mcp]`.
- Background service: `service.toml` (only listed targets can be scanned), Redis + RQ queue,
  `zues worker`, `zues scheduler` (`every = "24h"`), webhook alerts for fake fixes,
  reappearances and new urgent findings.
- Web API (`/api/v1`) and dashboard (`zues web`): viewer / operator tokens, HttpOnly
  SameSite session cookie with a CSRF header, strict CSP, the attack-surface map per run,
  finding decisions, audit chain check.
- Docker: non-root image (nmap with `cap_net_raw` only, read-only root filesystem in compose),
  dependencies pinned by hash, `compose.yaml` with Redis, web, worker, scheduler.
- `zues backup` (online, checked, rotated) and `--verify`.
- Vulnerable lab (`lab/`): Apache 2.4.49, OpenSSH 7.5, nginx 1.20.0 behind a real router, on
  isolated networks; `lab/up.sh`, `lab/demo.sh`, `lab/down.sh`; run end to end in CI.
- nuclei, subfinder and nuclei-templates pinned by version and SHA-256 (`zues_scan/data/tools.lock`):
  in the image, and on any machine with `zues tools install|verify|list|path` (no admin).
- nuclei checks non-web services (`address:port`, network templates only), runs signed
  templates only, records the templates' version; one time budget, partial results kept.
- `zues doctor`: what a machine can scan with, nmap's raw-socket rights, and the install
  command for this system.
- Plugins: registry with the `zues_scan.plugins` entry point group, `zues plugins`,
  `--scanner/--check/--discoverer`, a contract kit, an example plugin package
  (`examples/zues-exposed-git`), `docs/PLUGINS.md`.
- Scope directive `@activity passive|scan|active`; profile setting `check_rate`;
  `zues --version`.

### Changed
- **A scope allows up to `scan` by default: nuclei (an active check) now needs
  `@activity active` in the scope file.** Without it the scan is refused before anything is
  sent, and the refusal is recorded in the audit trail.
- A check that fails or runs out of time no longer fails the whole scan: the port scan is
  kept and the run is `partial`.
- A finding seen by nuclei and also matched by version keeps the CVE database's CVSS, KEV
  and EPSS (it used to drop them).
- Discovery considers at most `--discover-limit` names (1000), resolves them in parallel and
  drops wildcard-DNS matches.

### Fixed
- Dashboard: an answer arriving late for the page just left (e.g. the overview, when Redis
  is slow) was drawn over the page now shown; each visit now draws into its own element.
- A scanner that reported an incomplete result did not make the run partial (only checks
  did).
- `zues plugins` showed tools installed by `zues tools install` as not ready: it looked on
  PATH only, while the plugins themselves look in ZuesScan's tools directory first.
- The image had no SSH client (authenticated scans could not run in Docker).
- `subfinder -version` wrote a config file into the data volume.
- nmap installed on Windows but not yet on PATH is found.

## [0.1.0] - 2026-11-16

Never published as a release, and still called ReconKit; the state of `main` before the
service work. Command-line
scanner: scope guard, nmap with traceroute, CVE matching (NVD, KEV, EPSS,
priorities), finding lifecycle across runs, evidence and audit trail, HTML / JSON / SARIF
reports, authenticated Debian package checks.

[Unreleased]: https://github.com/B23DCAT011/reconkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/B23DCAT011/reconkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/B23DCAT011/reconkit/commits/main
