"""Baselines: compare a scan with an earlier report and tell new findings from known ones.

A baseline is a JSON report (``--format json``) or a SARIF report (``--format sarif``)
written by an earlier run. A finding is identified by component type, component slug
and Wordfence vulnerability id. The installed version is deliberately not part of the
key: updating a plugin to a release that is still affected by the same advisory does not
turn the finding into a new one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit import AuditResult, Finding

__all__ = [
    "Baseline",
    "BaselineComparison",
    "BaselineEntry",
    "BaselineError",
    "compare",
    "finding_key",
]

BaselineKey = tuple[str, str, str]

_TYPES = ("core", "plugin", "theme")


class BaselineError(ValueError):
    """The baseline file cannot be read or is not a wp-vuln-audit report."""


@dataclass(frozen=True)
class BaselineEntry:
    """A finding recorded in the baseline."""

    type: str
    slug: str
    id: str
    version: str | None = None
    title: str = ""
    severity: str = ""

    @property
    def key(self) -> BaselineKey:
        return (self.type, self.slug, self.id)

    @property
    def label(self) -> str:
        if self.type == "core":
            return f"WordPress {self.version or '?'}"
        return f"{self.type} {self.slug} {self.version or '?'}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title or None,
            "severity": self.severity or None,
            "component": {"type": self.type, "slug": self.slug, "version": self.version},
        }


def finding_key(finding: Finding) -> BaselineKey:
    return (finding.component.type, finding.component.slug, finding.vulnerability.id)


def _entry(ctype: Any, slug: Any, vid: Any, **extra: Any) -> BaselineEntry:
    if ctype not in _TYPES or not isinstance(slug, str) or not slug or not isinstance(vid, str) or not vid:
        raise BaselineError("finding without a component type, slug and vulnerability id")
    version = extra.get("version")
    return BaselineEntry(
        ctype,
        slug.lower(),
        vid,
        version if isinstance(version, str) else None,
        str(extra.get("title") or ""),
        str(extra.get("severity") or ""),
    )


@dataclass
class Baseline:
    """The set of findings an earlier run reported."""

    entries: list[BaselineEntry] = field(default_factory=list)
    source: str = ""
    format: str = "json"

    def __post_init__(self) -> None:
        unique: dict[BaselineKey, BaselineEntry] = {}
        for e in self.entries:
            unique.setdefault(e.key, e)
        self.entries = list(unique.values())
        self._keys = set(unique)

    def __contains__(self, key: object) -> bool:
        return key in self._keys

    def __len__(self) -> int:
        return len(self.entries)

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_report(cls, data: Any, source: str = "") -> Baseline:
        """Build a baseline from a parsed JSON or SARIF report."""
        if not isinstance(data, dict):
            raise BaselineError("expected a JSON object")
        if "runs" in data and str(data.get("version", "")).startswith("2."):
            return cls(_from_sarif(data), source, "sarif")
        tool = data.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != "wp-vuln-audit" or "findings" not in data:
            raise BaselineError("not a wp-vuln-audit JSON or SARIF report")
        entries: list[BaselineEntry] = []
        # Ignored findings are known too: a rule that expires must not make them look new.
        for section in ("findings", "ignored"):
            items = data.get(section, [])
            if items is None:
                items = []
            if not isinstance(items, list):
                raise BaselineError(f"'{section}' must be a list")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("component"), dict):
                    raise BaselineError(f"invalid entry in '{section}'")
                comp = item["component"]
                entries.append(
                    _entry(
                        comp.get("type"),
                        comp.get("slug"),
                        item.get("id"),
                        version=comp.get("version"),
                        title=item.get("title"),
                        severity=item.get("severity"),
                    )
                )
        return cls(entries, source, "json")

    @classmethod
    def from_text(cls, text: str, source: str = "") -> Baseline:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BaselineError(f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        return cls.from_report(data, source)

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise BaselineError(f"cannot read {path}: {exc.strerror or exc}") from exc
        try:
            return cls.from_text(text, str(path))
        except BaselineError as exc:
            raise BaselineError(f"{path}: {exc}") from exc


def _from_sarif(data: dict[str, Any]) -> list[BaselineEntry]:
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise BaselineError("SARIF 'runs' must be a list")
    entries: list[BaselineEntry] = []
    seen_tool = False
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        if driver.get("name") != "wp-vuln-audit":
            continue
        seen_tool = True
        for res in run.get("results") or []:
            if not isinstance(res, dict) or res.get("baselineState") == "absent":
                continue
            props = res.get("properties") or {}
            entries.append(
                _entry(
                    props.get("componentType"),
                    props.get("component"),
                    res.get("ruleId"),
                    version=props.get("installedVersion"),
                    severity=props.get("severity"),
                )
            )
    if not seen_tool:
        raise BaselineError("SARIF file has no wp-vuln-audit run")
    return entries


# ---------------------------------------------------------------------- comparing


@dataclass
class BaselineComparison:
    """Result of comparing the current findings with a baseline."""

    baseline: Baseline
    new: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    resolved: list[BaselineEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._new_ids = {id(f) for f in self.new}

    def is_new(self, finding: Finding) -> bool:
        return id(finding) in self._new_ids

    def state(self, finding: Finding) -> str:
        """SARIF ``baselineState`` of a current finding: ``new`` or ``unchanged``."""
        return "new" if self.is_new(finding) else "unchanged"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.baseline.source or None,
            "format": self.baseline.format,
            "entries": len(self.baseline),
            "new": len(self.new),
            "unchanged": len(self.unchanged),
            "resolved": [e.to_dict() for e in self.resolved],
        }


def compare(result: AuditResult, baseline: Baseline) -> BaselineComparison:
    """Split ``result.findings`` into new and unchanged, and list resolved baseline entries.

    Findings that are now ignored count as present, so they are neither new nor resolved.
    The comparison is stored on ``result.baseline`` and returned.
    """
    new: list[Finding] = []
    unchanged: list[Finding] = []
    for f in result.findings:
        (unchanged if finding_key(f) in baseline else new).append(f)
    present = {finding_key(f) for f in result.findings} | {finding_key(f) for f in result.ignored}
    resolved = [e for e in baseline.entries if e.key not in present]
    resolved.sort(key=lambda e: (e.type, e.slug, e.id))
    comparison = BaselineComparison(baseline, new, unchanged, resolved)
    result.baseline = comparison
    return comparison
