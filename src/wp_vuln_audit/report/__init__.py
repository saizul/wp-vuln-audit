"""Report renderers: text, JSON, Markdown and SARIF 2.1.0."""

from __future__ import annotations

from ..audit import AuditResult
from .json_report import render_json
from .markdown import render_markdown
from .sarif import render_sarif
from .text import render_text

__all__ = ["FORMATS", "render", "render_json", "render_markdown", "render_sarif", "render_text"]

FORMATS = ("text", "json", "markdown", "sarif")


def render(result: AuditResult, fmt: str, *, color: bool = False, show_ignored: bool = False) -> str:
    if fmt == "text":
        return render_text(result, color=color, show_ignored=show_ignored)
    if fmt == "json":
        return render_json(result)
    if fmt in ("markdown", "md"):
        return render_markdown(result, show_ignored=show_ignored)
    if fmt == "sarif":
        return render_sarif(result)
    raise ValueError(f"unknown format {fmt!r}, expected one of {', '.join(FORMATS)}")
