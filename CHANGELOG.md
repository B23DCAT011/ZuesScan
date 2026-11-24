# Changelog

All notable changes, per release. The format follows [Keep a Changelog](https://keepachangelog.com),
versions follow [Semantic Versioning](https://semver.org). The release workflow publishes the
section of a version as its release notes, so every tag needs one.

## [Unreleased]

### Fixed
- nuclei missed network flaws on busy servers: its network checks (SSH, TLS handshakes) ran
  with the HTTP settings, 10 s per request and one retry. Against a CPU-starved SSH server it
  missed Terrapin (CVE-2023-48795) on 4 of 10 runs — the lab's CI job failed twice that way.
  The network run now waits 30 s with 3 retries (5 of 5); web checks keep 10 s / 1, and the
  check's overall time budget is unchanged.

### Added
- Every change of a scope, target or token — in the dashboard or with `zues user` — raises a
  `config_changed` alert (who, what), queued in the same transaction as its audit event: one
  admin can widen what may be scanned, and now the others know at once.

### Security
- Tokens expire. A token made in the dashboard or with `zues user add` is accepted for 90
  days by default (30 days, 1 year, up to 2 years, or `never` for a monitored service
  account; schema 17); `service.toml` tokens take an optional `expires = 2027-06-30`. An
  expired token is refused with its date (not counted as a guess), and the sessions opened
  with it end. A week before, the scheduler raises a `token_expiring` alert.
- Tokens are rotated: Settings → Tokens → **Rotate**, `zues user rotate NAME`,
  `POST /api/v1/admin/tokens/{name}/rotate` give a new value under the same name and role;
  the old value, and every session opened with it, stop working at once. Audited.

### Changed
- `zues user add` takes `--expires` (default 90d); `zues user list` shows when each token
  expires.

### Security
- Evidence is masked before it is stored and hashed: the requests and responses nuclei
  keeps when it confirms a flaw no longer carry the target's credentials and secrets
  (`Authorization`, `Cookie` / `Set-Cookie` values, headers named after tokens, secrets or
  sessions; `password=`-style pairs, bearer tokens and JWTs, AWS keys, PEM private keys,
  `/etc/shadow` hashes, passwords in URLs), and a response body is cut to 2 KB with a note.
  A match with nothing to mask is kept byte for byte. `zues_scan/redact.py`.

### Added
- Compare runs in the dashboard: a run's **Changes** (against the run of the same target
  before it) or any two runs ticked in Runs: hosts that appeared or went away, ports opened
  or closed, software versions that changed, findings that appeared or went away, with the
  caveats `zues diff` gives when runs are not comparable. API:
  `GET /api/v1/runs/{id}/diff[?against=<id>]`; MCP tool `compare_runs`.
- Pages: `GET /api/v1/runs?before=<id>` (the dashboard's **Older runs**) and
  `GET /api/v1/findings?limit=&offset=` with `X-Total-Count` (**Show more**). Without them the
  answers are what they were.

### Added
- `cron` schedules for targets, instead of `every`: `cron = "0 2 * * sat Asia/Ho_Chi_Minh"`
  — the five crontab fields (lists, ranges, steps, month and day names; day of month OR day
  of week when both are set), with an optional time zone (IANA name with daylight saving
  time, `UTC` or `+07:00`). At least 5 minutes between scans. In service.toml, the API and
  the dashboard (the Schedule box takes `24h` or a cron line). `zues-scan[server]` installs
  `tzdata` on Windows, which has no time zone data of its own.

### Fixed
- Scheduled scans drifted: a target was due `every` after its last scan *started* (or was
  queued), so a scan that waited 40 minutes in the queue moved every later one by 40
  minutes. The scheduler now keeps each target's slot: due at the last slot + `every`,
  whenever the scan actually ran; several missed slots are made up with one scan.

### Changed
- The database uses write-ahead logging: a long read (the dashboard, a report) no longer
  holds back the save of a run, and saves no longer block readers; a busy database is
  waited on for 15 seconds (was 5). Set when a database is created or migrated, and by
  `web`, `worker` and `scheduler` at start (e.g. after a restore) — never by merely opening
  one, so reading a backup leaves it byte for byte as hashed. Backups are written as one
  self-contained file. `zues doctor` reports a database that is not in WAL mode. Restoring:
  delete the old `zues.db-wal` / `zues.db-shm` first (README).
- `zues doctor` checks the service that `$ZUES_CONFIG` or the `ZUES_*` variables describe
  when no `--config` is given: in the image (`docker compose exec web zues doctor`) it now
  checks the database and Redis too.

### Added
- Alerts are no longer lost: they wait in the database (`alert_outbox`, schema 16) until the
  webhook takes them. A scan's alerts are saved in the same transaction as its run; the
  worker sends them right away and the scheduler retries what failed at every round (after
  1, 2, 4 ... minutes, at most an hour apart, `Retry-After` honoured), giving up after 24
  hours, or at once on a 4xx that retrying cannot change or a redirect. Every retry carries
  the same `X-ZuesScan-Delivery` id for receivers to deduplicate on.
- Signed alerts: with `[notify] secret` (or `ZUES_WEBHOOK_SECRET`) every POST carries
  `X-ZuesScan-Timestamp` and `X-ZuesScan-Signature: sha256=HMAC(secret, "<ts>." + body)`;
  `zues_scan.server.notify.verify()` is the receiver's check.
- New alerts: a target's scans failing `failed_scans` times in a row (default 3, once) and
  working again; a scan not started (refused by its scope, e.g. an expired authorisation;
  once a day); a scan job that failed without saving a run (RQ's failure callback; once
  every 6 hours); an address locked out of the dashboard (once an hour); a test alert.
- Settings → **Alerts**: where alerts go (host only), whether they are signed, each alert's
  delivery state, **Send now**, **Send a test alert**. API: `GET /api/v1/admin/alerts`,
  `POST /api/v1/admin/alerts/test`, `POST /api/v1/admin/alerts/{id}/retry`.
- compose.yaml passes ZUES_WEBHOOK, ZUES_WEBHOOK_SECRET, ZUES_NOTIFY_MIN_PRIORITY and
  ZUES_NOTIFY_FAILED_SCANS (e.g. from a `.env` file): the three-command install can alert.

### Changed
- `zues scheduler --once` also sends the alerts that are due, and says how many.
- The webhook is posted without following redirects (a redirect would drop the POST's body).

### Fixed
- The scheduler read its configuration once, at start: a target added or changed in the
  dashboard (or in service.toml) was never scheduled until the scheduler restarted — the
  three-command install's "add a target, every 24h" did not scan. It now re-reads the
  configuration at every round; an invalid one schedules nothing until it is fixed.

### Security
- The dashboard's sessions are held by the server: the cookie carries only a random
  session key (its SHA-256 is stored, never the key, never the token). A session ends when
  its owner signs out (on the server: a copied cookie stops working), after 30 minutes
  without use (the page's own refresh does not count), 8 hours after signing in, when its
  token is revoked or re-issued, or when an admin ends it. Database schema 15.
- Failed sign-ins are braked: 10 wrong tokens (sign-in form or `Authorization: Bearer`)
  within 15 minutes lock the address out for 15 minutes (429 with Retry-After, even for a
  right token). Counted in Redis, in the process when Redis is down; logged
  (`auth.locked`) and audited.

### Added
- Settings → **Sessions**: who is signed in, from where, since when, until when; **End**
  ends a session. API: `GET /api/v1/admin/sessions`, `DELETE /api/v1/admin/sessions/{id}`.
- Audit kind `auth`: signed in, signed out, session ended (by whom), address locked out.

### Changed
- `DELETE /api/v1/session` with the session cookie needs the `X-ZuesScan: 1` header, like
  every other change made with the cookie.

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
