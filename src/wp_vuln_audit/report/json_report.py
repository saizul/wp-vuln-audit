from __future__ import annotations

import json
from typing import Any

from .._version import __version__
from ..audit import AuditResult

SCHEMA_VERSION = 1


def result_to_dict(result: AuditResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "wp-vuln-audit", "version": __version__},
        "target": result.inventory.target,
        "feed": result.feed_info or None,
        "summary": {
            "components": len(result.inventory),
            "vulnerable_components": len(result.vulnerable_components),
            "findings": len(result.findings),
            "ignored": len(result.ignored),
            "filtered": result.filtered,
            "unchecked": len(result.unchecked),
            "highest_severity": result.highest(),
            "by_severity": {k: v for k, v in result.counts().items() if v},
        },
        "components": [c.to_dict() for c in result.inventory.components],
        "findings": [f.to_dict() for f in result.findings],
        "ignored": [f.to_dict() for f in result.ignored],
        "unchecked": [c.to_dict() for c in result.unchecked],
        "warnings": list(result.warnings),
    }


def render_json(result: AuditResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, ensure_ascii=False) + "\n"
