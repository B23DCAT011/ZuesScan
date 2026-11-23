# Changelog

All notable changes, per release. The format follows [Keep a Changelog](https://keepachangelog.com),
versions follow [Semantic Versioning](https://semver.org). The release workflow publishes the
section of a version as its release notes, so every tag needs one.

## [Unreleased]

### Added
- `reconkit mcp`: ReconKit as tools for AI agents over the Model Context Protocol (stdio),
  as a client of the web API. Queueing a scan, claiming a fix and reopening a finding need
  the user's confirmation through the MCP client; risk acceptance is not offered to agents;
  only configured targets can be scanned; scan data is cleaned and marked as untrusted.
  Install with `reconkit[mcp]`.

## [0.2.0] - 2026-11-23

The first release meant to be installed by others: a service, a web dashboard, a hardened
image, real nuclei / subfinder integration, plugins, and a vulnerable lab to try it on.

### Added
- Background service: `service.toml` (only listed targets can be scanned), Redis + RQ queue,
  `reconkit worker`, `reconkit scheduler` (`every = "24h"`), webhook alerts for fake fixes,
  reappearances and new urgent findings.
- Web API (`/api/v1`) and dashboard (`reconkit web`): viewer / operator tokens, HttpOnly
  SameSite session cookie with a CSRF header, strict CSP, the attack-surface map per run,
  finding decisions, audit chain check.
- Docker: non-root image (nmap with `cap_net_raw` only, read-only root filesystem in compose),
  dependencies pinned by hash, `compose.yaml` with Redis, web, worker, scheduler.
- `reconkit backup` (online, checked, rotated) and `--verify`.
- Vulnerable lab (`lab/`): Apache 2.4.49, OpenSSH 7.5, nginx 1.20.0 behind a real router, on
  isolated networks; `lab/up.sh`, `lab/demo.sh`, `lab/down.sh`; run end to end in CI.
- nuclei, subfinder and nuclei-templates pinned by version and SHA-256 (`reconkit/data/tools.lock`):
  in the image, and on any machine with `reconkit tools install|verify|list|path` (no admin).
- nuclei checks non-web services (`address:port`, network templates only), runs signed
  templates only, records the templates' version; one time budget, partial results kept.
- `reconkit doctor`: what a machine can scan with, nmap's raw-socket rights, and the install
  command for this system.
- Plugins: registry with the `reconkit.plugins` entry point group, `reconkit plugins`,
  `--scanner/--check/--discoverer`, a contract kit, an example plugin package
  (`examples/reconkit-exposed-git`), `docs/PLUGINS.md`.
- Scope directive `@activity passive|scan|active`; profile setting `check_rate`;
  `reconkit --version`.

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
- The image had no SSH client (authenticated scans could not run in Docker).
- `subfinder -version` wrote a config file into the data volume.
- nmap installed on Windows but not yet on PATH is found.

## [0.1.0] - 2026-11-16

Never published as a release; the state of `main` before the service work. Command-line
scanner: scope guard, nmap with traceroute, CVE matching (NVD, KEV, EPSS,
priorities), finding lifecycle across runs, evidence and audit trail, HTML / JSON / SARIF
reports, authenticated Debian package checks.

[Unreleased]: https://github.com/B23DCAT011/reconkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/B23DCAT011/reconkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/B23DCAT011/reconkit/commits/main
