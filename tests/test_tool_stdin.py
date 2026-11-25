"""No external tool may read ZuesScan's own stdin. httpx reads stdin as more input when it
is not a terminal: from a script with a pipe that stays open (cron, CI, `... | while
read`), a check waited until its whole time limit and returned nothing (measured with
httpx 1.12.0: 30 s with an open pipe, 0.6 s with /dev/null). ssh reads it too. Every
subprocess call either feeds its input or gets /dev/null."""

from __future__ import annotations

import ast
from pathlib import Path

import zues_scan

CALLS = ("run", "Popen", "check_output", "call", "check_call")


def test_every_tool_gets_its_own_stdin() -> None:
    root = Path(zues_scan.__file__).parent
    missing = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in CALLS
                and getattr(node.func.value, "id", "") == "subprocess"
                and not {"input", "stdin"} & {k.arg for k in node.keywords}
            ):
                missing.append(f"{path.relative_to(root)}:{node.lineno}")
    assert missing == [], "subprocess calls without stdin= or input=: " + ", ".join(missing)
