from __future__ import annotations

from ..audit import AuditResult, Finding


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _fix(f: Finding) -> str:
    if f.fixed_in:
        return f"Update to {f.fixed_in}"
    if f.software.remediation:
        return f.software.remediation
    return "No fix available" if not f.software.patched else "See advisory"


def render_markdown(result: AuditResult, *, show_ignored: bool = False) -> str:
    out: list[str] = ["## WordPress vulnerability audit", ""]
    inv = result.inventory
    counts = inv.counts()
    if inv.target:
        out.append(f"Target: `{inv.target}`")
        out.append("")
    out.append(
        f"Checked {'WordPress core, ' if counts['core'] else ''}{counts['plugin']} plugin(s) "
        f"and {counts['theme']} theme(s)."
    )
    out.append("")
    if not result.findings:
        out.append("No known vulnerabilities found.")
    else:
        c = result.counts()
        badges = ", ".join(f"**{c[s]}** {s}" for s in ("critical", "high", "medium", "low", "none", "unknown") if c[s])
        out.append(
            f"Found **{len(result.findings)}** vulnerabilities in "
            f"{len(result.vulnerable_components)} component(s): {badges}."
        )
        out.append("")
        out.append("| Severity | Component | Installed | Vulnerability | Fix |")
        out.append("| --- | --- | --- | --- | --- |")
        for f in result.findings:
            sev = f.severity.capitalize() + (f" ({f.score:.1f})" if f.score is not None else "")
            title = f"[{_cell(f.vulnerability.title)}]({f.vulnerability.url})"
            if f.vulnerability.cve:
                title += f" {f.vulnerability.cve}"
            if result.baseline is not None and result.baseline.is_new(f):
                title = f"**New:** {title}"
            comp = "WordPress core" if f.component.type == "core" else f"{f.component.type} `{f.component.slug}`"
            out.append(f"| {sev} | {comp} | {f.component.version} | {title} | {_cell(_fix(f))} |")
    out.append("")
    if result.baseline is not None:
        b = result.baseline
        out.append(
            f"Compared with the baseline: **{len(b.new)}** new, {len(b.unchanged)} unchanged, "
            f"{len(b.resolved)} resolved."
        )
        out.append("")
        if b.resolved:
            out.append("<details><summary>Resolved since the baseline</summary>")
            out.append("")
            for e in b.resolved:
                title = f": {_cell(e.title)}" if e.title else ""
                out.append(f"- {e.label}{title} (`{e.id}`)")
            out.append("")
            out.append("</details>")
            out.append("")
    if show_ignored and result.ignored:
        out.append("<details><summary>Ignored findings</summary>")
        out.append("")
        for f in result.ignored:
            reason = f" - {f.ignored_by.reason}" if f.ignored_by and f.ignored_by.reason else ""
            out.append(f"- {f.component.label}: {_cell(f.vulnerability.title)}{reason}")
        out.append("")
        out.append("</details>")
        out.append("")
    if result.unchecked:
        names = ", ".join(f"`{c.slug}`" for c in result.unchecked)
        out.append(f"Not checked (version unknown): {names}")
        out.append("")
    out.append("Vulnerability data: [Wordfence Intelligence](https://www.wordfence.com/threat-intel/vulnerabilities/).")
    return "\n".join(out) + "\n"
