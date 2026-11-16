from __future__ import annotations

from ..audit import AuditResult, Finding

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "none": "\033[2m",
    "unknown": "\033[2m",
}
_RESET = "\033[0m"


def _sev(finding: Finding, color: bool) -> str:
    label = finding.severity.upper()
    if finding.score is not None:
        label += f" {finding.score:.1f}"
    padded = f"{label:<13}"
    if color:
        return f"{_COLORS.get(finding.severity, '')}{padded}{_RESET}"
    return padded


def _fix(finding: Finding) -> str:
    if finding.fixed_in:
        return f"fixed in {finding.fixed_in}"
    if finding.software.remediation:
        return finding.software.remediation
    return "no fix available" if not finding.software.patched else "patched (see advisory)"


def render_text(result: AuditResult, *, color: bool = False, show_ignored: bool = False) -> str:
    lines: list[str] = []
    inv = result.inventory
    counts = inv.counts()
    target = inv.target or "inventory"
    lines.append(
        f"Scanned {target}: core {'yes' if counts['core'] else 'no'}, "
        f"{counts['plugin']} plugin(s), {counts['theme']} theme(s)"
    )
    if result.feed_info:
        info = result.feed_info
        if info.get("status") == "file":
            lines.append(f"Feed: {info.get('file', 'file')} ({info.get('records', '?')} records)")
        else:
            lines.append(f"Feed: {info.get('variant', '?')} ({info.get('records', '?')} records, {info.get('status')})")
    lines.append("")

    # Group by component; components keep the order of their most severe finding.
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in result.findings:
        groups.setdefault(f.component.key, []).append(f)
    for findings in groups.values():
        comp = findings[0].component
        where = f" [{comp.location}]" if comp.location else ""
        lines.append(f"{comp.label}{where}")
        for f in findings:
            cve = f" {f.vulnerability.cve}" if f.vulnerability.cve else ""
            new = " [new]" if result.baseline is not None and result.baseline.is_new(f) else ""
            lines.append(f"  {_sev(f, color)} {f.vulnerability.title}{cve}{new}")
            lines.append(f"  {'':13} affected {f.range.describe()}; {_fix(f)}")
            lines.append(f"  {'':13} {f.vulnerability.url}")
    if result.findings:
        lines.append("")

    if show_ignored and result.ignored:
        lines.append("Ignored:")
        for f in result.ignored:
            reason = f" ({f.ignored_by.reason})" if f.ignored_by and f.ignored_by.reason else ""
            rule = f.ignored_by.describe() if f.ignored_by else "?"
            lines.append(f"  {f.component.label}: {f.vulnerability.title} [rule {rule}]{reason}")
        lines.append("")

    if result.baseline is not None and result.baseline.resolved:
        lines.append("Resolved since the baseline:")
        for e in result.baseline.resolved:
            title = f": {e.title}" if e.title else ""
            lines.append(f"  {e.label}{title} ({e.id})")
        lines.append("")

    for c in result.unchecked:
        lines.append(f"not checked: {c.type} {c.slug} (version unknown)")
    for w in result.warnings:
        if "version unknown" in w:
            continue
        lines.append(f"warning: {w}")
    if result.unchecked or result.warnings:
        lines.append("")

    if result.findings:
        c = result.counts()
        parts = [f"{c[s]} {s}" for s in ("critical", "high", "medium", "low", "none", "unknown") if c[s]]
        lines.append(
            f"{len(result.findings)} vulnerabilit{'y' if len(result.findings) == 1 else 'ies'} in "
            f"{len(result.vulnerable_components)} component(s): {', '.join(parts)}"
        )
    else:
        lines.append("No known vulnerabilities found.")
    extras = []
    if result.baseline is not None:
        b = result.baseline
        extras.append(f"{len(b.new)} new, {len(b.unchanged)} unchanged, {len(b.resolved)} resolved since the baseline")
    if result.ignored:
        extras.append(f"{len(result.ignored)} ignored")
    if result.filtered:
        extras.append(f"{result.filtered} below the severity filter")
    if extras:
        lines.append(f"({', '.join(extras)})")
    return "\n".join(lines) + "\n"
