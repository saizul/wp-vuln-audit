"""Matching an inventory against the feed and filtering the result."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .feed import SEVERITIES, Feed, Software, Vulnerability, severity_rank
from .ignore import IgnoreList, IgnoreRule
from .inventory import Component, Inventory
from .ranges import VersionRange

if TYPE_CHECKING:
    from .baseline import BaselineComparison
    from .upgrade import Upgrade

__all__ = ["AuditOptions", "AuditResult", "Finding", "audit", "check_component"]


@dataclass(frozen=True)
class Finding:
    component: Component
    vulnerability: Vulnerability
    software: Software
    range: VersionRange
    fixed_in: str | None
    ignored_by: IgnoreRule | None = None

    @property
    def severity(self) -> str:
        return self.vulnerability.severity

    @property
    def score(self) -> float | None:
        return self.vulnerability.score

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            -severity_rank(self.severity),
            -(self.score or 0.0),
            self.component.type,
            self.component.slug,
            self.vulnerability.id,
        )

    def to_dict(self) -> dict[str, Any]:
        v = self.vulnerability
        data: dict[str, Any] = {
            "id": v.id,
            "title": v.title,
            "severity": self.severity,
            "cvss": None
            if v.cvss is None
            else {"score": v.cvss.score, "vector": v.cvss.vector, "rating": v.cvss.rating},
            "cve": v.cve,
            "cwe": None if v.cwe is None else {"id": v.cwe.id, "name": v.cwe.name},
            "component": self.component.to_dict(),
            "affected": self.range.describe(),
            "affected_range": self.range.to_dict(),
            "patched": self.software.patched,
            "fixed_in": self.fixed_in,
            "remediation": self.software.remediation or None,
            "informational": v.informational,
            "published": v.published,
            "updated": v.updated,
            "url": v.url,
            "references": list(v.references),
        }
        if self.ignored_by is not None:
            data["ignored_by"] = {"rule": self.ignored_by.describe(), "reason": self.ignored_by.reason}
        return data


@dataclass
class AuditOptions:
    min_severity: str = "unknown"
    min_cvss: float | None = None
    # None: keep records without CVSS only when no severity or score filter is set.
    include_unscored: bool | None = None
    include_informational: bool = False
    ignore: IgnoreList | None = None
    today: _dt.date | None = None

    def __post_init__(self) -> None:
        if self.min_severity not in SEVERITIES:
            raise ValueError(f"min_severity must be one of {', '.join(SEVERITIES)}")


@dataclass
class AuditResult:
    inventory: Inventory
    findings: list[Finding] = field(default_factory=list)
    ignored: list[Finding] = field(default_factory=list)
    filtered: int = 0
    unchecked: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    feed_info: dict[str, Any] = field(default_factory=dict)
    # Set by ``baseline.compare()``.
    baseline: BaselineComparison | None = None
    # One entry per vulnerable component, set by ``audit()``.
    upgrades: list[Upgrade] = field(default_factory=list)

    @property
    def vulnerable_components(self) -> list[Component]:
        seen: dict[tuple[str, str], Component] = {}
        for f in self.findings:
            seen.setdefault(f.component.key, f.component)
        return list(seen.values())

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def highest(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def fails(self, threshold: str, *, new_only: bool = False) -> bool:
        """True when a finding is at or above ``threshold`` (``never`` disables).

        With ``new_only`` and a baseline comparison, only findings that are not in the
        baseline count.
        """
        if threshold == "never":
            return False
        findings = self.findings
        if new_only and self.baseline is not None:
            findings = [f for f in findings if self.baseline.is_new(f)]
        if threshold == "any":
            return bool(findings)
        rank = severity_rank(threshold)
        return any(severity_rank(f.severity) >= rank for f in findings)


def check_component(feed: Feed, component: Component) -> list[Finding]:
    """Every vulnerability in ``feed`` that affects ``component`` (no filtering)."""
    if not component.version:
        return []
    found: list[Finding] = []
    seen: set[str] = set()
    for vuln, sw in feed.for_component(component.type, component.slug):
        if vuln.id in seen:
            continue
        rng = sw.matching_range(component.version)
        if rng is None:
            continue
        seen.add(vuln.id)
        found.append(Finding(component, vuln, sw, rng, sw.fixed_in(component.version)))
    return found


def _passes(finding: Finding, opts: AuditOptions) -> bool:
    v = finding.vulnerability
    if v.informational and not opts.include_informational:
        return False
    if v.cvss is None:
        if opts.include_unscored is not None:
            return opts.include_unscored
        return opts.min_cvss is None and opts.min_severity in ("unknown", "none")
    if opts.min_cvss is not None and v.cvss.score < opts.min_cvss:
        return False
    return severity_rank(finding.severity) >= severity_rank(opts.min_severity)


def audit(feed: Feed, inventory: Inventory, options: AuditOptions | None = None) -> AuditResult:
    opts = options or AuditOptions()
    result = AuditResult(inventory=inventory, warnings=list(inventory.warnings))
    if opts.ignore is not None:
        for rule in opts.ignore.expired(opts.today):
            result.warnings.append(
                f"ignore rule {rule.describe()} (line {rule.line}) expired on "
                f"{rule.expires.isoformat() if rule.expires else '?'}"
            )
    for comp in inventory.components:
        if not comp.version:
            result.unchecked.append(comp)
            continue
        for finding in check_component(feed, comp):
            if not _passes(finding, opts):
                result.filtered += 1
                continue
            rule = opts.ignore.match(finding.vulnerability, comp, opts.today) if opts.ignore else None
            if rule is not None:
                result.ignored.append(
                    Finding(
                        finding.component,
                        finding.vulnerability,
                        finding.software,
                        finding.range,
                        finding.fixed_in,
                        rule,
                    )
                )
                continue
            result.findings.append(finding)
    result.findings.sort(key=lambda f: f.sort_key)
    result.ignored.sort(key=lambda f: f.sort_key)
    from .upgrade import plan_upgrades

    result.upgrades = plan_upgrades(feed, result.findings)
    return result
