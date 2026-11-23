"""Reports of a scan run: the attack-surface map (HTML) and the data behind it."""

from zues_scan.report.html import render_html
from zues_scan.report.model import report_model, stored_model

__all__ = ["render_html", "report_model", "stored_model"]
