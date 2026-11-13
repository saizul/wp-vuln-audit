"""Use wp-vuln-audit as a library.

Run from the repository root:

    python examples/library_usage.py
"""

from __future__ import annotations

from pathlib import Path

from wp_vuln_audit import AuditOptions, Feed, audit, render, scan_local

HERE = Path(__file__).parent

feed = Feed.from_file(str(HERE / "feed-sample.json"))
inventory = scan_local(HERE / "sample-site")

result = audit(feed, inventory, AuditOptions(min_severity="medium"))

print(render(result, "text"))
for finding in result.findings:
    print(finding.component.slug, finding.vulnerability.cve, finding.severity, "->", finding.fixed_in)
