"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Each vulnerability becomes a rule (``ruleId`` is the Wordfence id) with a
``security-severity`` property holding the CVSS score, which GitHub uses to show
Critical / High / Medium / Low. Each finding is a result located at the file the
component version was read from (the plugin main file, ``style.css`` or
``wp-includes/version.php``).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .._version import __version__
from ..audit import AuditResult, Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "none": "note"}
_DEFAULT_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "none": 0.0, "unknown": 5.0}


def _level(f: Finding) -> str:
    return _LEVELS.get(f.severity, "warning")


def _rule(f: Finding) -> dict[str, Any]:
    v = f.vulnerability
    score = v.score if v.score is not None else _DEFAULT_SCORE.get(f.severity, 5.0)
    tags = ["security", "wordpress", f.component.type]
    if v.cwe and v.cwe.id is not None:
        tags.append(f"external/cwe/cwe-{v.cwe.id}")
    help_lines = [v.title, "", v.description or "", "", f"Advisory: {v.url}"]
    if v.cve:
        help_lines.append(f"{v.cve}: {v.cve_link or 'https://www.cve.org/CVERecord?id=' + v.cve}")
    rule: dict[str, Any] = {
        "id": v.id,
        "name": "WordPressVulnerability",
        "shortDescription": {"text": v.title[:1000]},
        "fullDescription": {"text": (v.description or v.title)[:4000]},
        "helpUri": v.url,
        "help": {"text": "\n".join(line for line in help_lines if line is not None).strip()},
        "defaultConfiguration": {"level": _level(f)},
        "properties": {"security-severity": f"{score:.1f}", "tags": tags, "precision": "high"},
    }
    return rule


def _fingerprint(f: Finding) -> str:
    raw = f"{f.vulnerability.id}|{f.component.type}|{f.component.slug}|{f.component.version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _location(f: Finding) -> dict[str, Any]:
    uri = f.component.location or (
        "wp-includes/version.php"
        if f.component.type == "core"
        else f"wp-content/{f.component.type}s/{f.component.slug}"
    )
    loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if not uri.startswith(("http://", "https://")):
        loc["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
        loc["physicalLocation"]["region"] = {"startLine": 1}
    return loc


def sarif_document(result: AuditResult) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        if f.vulnerability.id not in index:
            index[f.vulnerability.id] = len(rules)
            rules.append(_rule(f))
        fix = f"Update to {f.fixed_in}." if f.fixed_in else (f.software.remediation or "No patched version is known.")
        entry: dict[str, Any] = {
            "ruleId": f.vulnerability.id,
            "ruleIndex": index[f.vulnerability.id],
            "level": _level(f),
            "message": {
                "text": f"{f.component.label} is affected by {f.vulnerability.title}"
                + (f" ({f.vulnerability.cve})" if f.vulnerability.cve else "")
                + f". Affected: {f.range.describe()}. {fix}"
            },
            "locations": [_location(f)],
            "partialFingerprints": {"wpVulnAudit/v1": _fingerprint(f)},
            "properties": {
                "component": f.component.slug,
                "componentType": f.component.type,
                "installedVersion": f.component.version,
                "fixedIn": f.fixed_in,
                "severity": f.severity,
            },
        }
        if result.baseline is not None:
            entry["baselineState"] = result.baseline.state(f)
        results.append(entry)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wp-vuln-audit",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/saizul/wp-vuln-audit",
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


def render_sarif(result: AuditResult) -> str:
    return json.dumps(sarif_document(result), indent=2, ensure_ascii=False) + "\n"
