"""Render the report model as one self-contained HTML file.

The file opens offline and on any machine: the data (JSON), the page's script and
stylesheet and Cytoscape.js are all inlined. Python side: standard library only.

Everything in the data came from scanned machines, which may be hostile: a banner
can say `</script><script>...`. Three layers keep that from running:

1. The data sits in a `<script type="application/json">` block, never executed, with
   every `<`, `>` and `&` escaped as `\\u003c`... so it cannot close its block.
2. The page script only ever puts that data into the page as text (`textContent`,
   canvas labels), never as markup.
3. A Content-Security-Policy allows only the inlined scripts and styles whose SHA-256
   is listed, and no network access at all (`default-src 'none'`): even injected code
   would not run, and nothing in the report can phone home.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from importlib import resources
from typing import Any

_PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")


def render_html(model: dict[str, Any]) -> str:
    """The report page for `model` (see :func:`reconkit.report.model.report_model`)."""
    css = _read("assets/report.css")
    script = _read("assets/report.js")
    cytoscape = _read("vendor/cytoscape.min.js")
    for name, text in (("report.js", script), ("cytoscape.min.js", cytoscape)):
        if "</script" in text.lower() or "<!--" in text:
            # Either would end (or confuse) the inline <script> element early.
            raise ValueError(f"{name} cannot be inlined in a <script> element")

    run = model["run"]
    csp = page_csp()
    parts = {
        "TITLE": html.escape(f"ReconKit — run #{run['id']} — {run['target']}"),
        "CSP": html.escape(csp),
        "CSS": css,
        "DATA": json_for_html(model),
        "CYTOSCAPE": cytoscape,
        "SCRIPT": script,
    }
    # One pass over the template only: text that was just put in (scan data that
    # happens to contain "{{SCRIPT}}") is never searched for placeholders again.
    return _PLACEHOLDER.sub(lambda m: parts[m.group(1)], _read("assets/template.html"))


def page_csp() -> str:
    """The report page's Content-Security-Policy: only its own inlined scripts and
    stylesheet (by SHA-256), no network at all. The same for every report."""
    scripts = (_read("vendor/cytoscape.min.js"), _read("assets/report.js"))
    return "; ".join(
        [
            "default-src 'none'",
            f"script-src {' '.join(_hash(text) for text in scripts)}",
            f"style-src {_hash(_read('assets/report.css'))}",
            "img-src data:",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )


def json_for_html(data: Any) -> str:
    """JSON that is safe inside a `<script>` element of an HTML page.

    `<`, `>` and `&` become `\\u003c`, `\\u003e`, `\\u0026` (only ever inside strings,
    where JSON allows the escape), so no `</script>` or `<!--` can appear. U+2028 and
    U+2029 are escaped too: valid in JSON, but line breaks to older JavaScript.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for char, escaped in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        (" ", "\\u2028"),
        (" ", "\\u2029"),
    ):
        text = text.replace(char, escaped)
    return text


def _hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def _read(name: str) -> str:
    return resources.files("reconkit.report").joinpath(name).read_text(encoding="utf-8")
