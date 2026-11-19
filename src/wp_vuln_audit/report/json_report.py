from __future__ import annotations

import json
from typing import Any

from .._version import __version__
from ..audit import AuditResult, Finding

SCHEMA_VERSION = 1


def _finding(result: AuditResult, f: Finding) -> dict[str, Any]:
    data = f.to_dict()
    if result.baseline is not None:
        data["baseline_state"] = result.baseline.state(f)
    return data


def result_to_dict(result: AuditResult) -> dict[str, Any]:
    data: dict[str, Any] = {
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
        "findings": [_finding(result, f) for f in result.findings],
        "ignored": [f.to_dict() for f in result.ignored],
        "upgrades": [u.to_dict() for u in result.upgrades],
        "unchecked": [c.to_dict() for c in result.unchecked],
        "warnings": list(result.warnings),
    }
    if result.baseline is not None:
        data["baseline"] = result.baseline.to_dict()
        data["summary"]["new"] = len(result.baseline.new)
        data["summary"]["resolved"] = len(result.baseline.resolved)
    return data


def render_json(result: AuditResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, ensure_ascii=False) + "\n"
