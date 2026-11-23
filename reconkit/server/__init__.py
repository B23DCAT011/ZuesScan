"""ReconKit as a background service (phase 3): scheduled scans, a queue, workers, a web API.

Install with `pip install reconkit[server]` (FastAPI, uvicorn, Redis, RQ). The scanning
core stays dependency-free: the job a worker runs (`jobs.scan_target`) is the same
`scanning.execute` the CLI calls.

    scheduler ──enqueue──> Redis (RQ queue) ──> worker(s) ──> scanning.execute ──> SQLite
         ▲                                                          │
         └─ service.toml: targets, schedules, tokens, notifications ┘──> webhook alerts
    web API (FastAPI) ── reads the database, enqueues scans of *configured* targets
"""
