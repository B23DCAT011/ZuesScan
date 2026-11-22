"""Logging setup (G19): what ReconKit did, for whoever runs or operates it.

The CLI's own output (summaries, errors) is for the person at the terminal. Logs are
the operator's record: which command ran, how long each stage took, what was
retried — on stderr when asked (`-v` info, `-vv` debug) and, in full, in a log file.

Every module logs through `logging.getLogger(__name__)` (all under "reconkit").
`--log-format json` writes one JSON object per line, ready for a log collector when
ReconKit runs as a service.

Never logged: API keys and tokens. A scanner's raw output is not logged either (it is
kept, hashed, in the database); logs say where to find it.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

ROOT = "reconkit"
_TEXT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# Attributes every LogRecord has; anything else was passed with `extra=`.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger, message, and any `extra` fields."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                data[key] = (
                    value if isinstance(value, str | int | float | bool | None) else str(value)
                )
        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def setup(verbosity: int = 0, log_file: str | None = None, fmt: str = "text") -> None:
    """Configure the "reconkit" loggers: stderr by verbosity, the file at debug level."""
    logger = logging.getLogger(ROOT)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter: logging.Formatter = JsonFormatter() if fmt == "json" else logging.Formatter(_TEXT)
    console = logging.StreamHandler()
    console.setLevel(
        logging.WARNING if verbosity <= 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    )
    console.setFormatter(formatter)
    logger.addHandler(console)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
