from __future__ import annotations

import json

import pytest

from tests.conftest import vid
from wp_vuln_audit.audit import AuditOptions, AuditResult, audit
from wp_vuln_audit.feed import Feed
from wp_vuln_audit.ignore import IgnoreList
from wp_vuln_audit.inventory import Component, Inventory
from wp_vuln_audit.report import FORMATS, render


@pytest.fixture
def result(feed: Feed) -> AuditResult:
    inv = Inventory(
        [
            Component("core", "wordpress", "6.4.2", "WordPress", "wp-includes/version.php"),
            Component(
                "plugin",
                "example-forms",
                "2.0.3",
                "Example Forms",
                "wp-content/plugins/example-forms/example-forms.php",
            ),
            Component("plugin", "demo-slider", "4.2", "Demo Slider", "wp-content/plugins/demo-slider/demo-slider.php"),
            Component("theme", "demo-theme", "1.2", "Demo Theme", "wp-content/themes/demo-theme/style.css"),
            Component("plugin", "mystery", None),
        ],
        target="/srv/www/site",
        warnings=["plugin mystery: version unknown, not checked", "something else"],
    )
    ig = IgnoreList.parse('CVE-2026-20002 reason="admin only"')
    res = audit(feed, inv, AuditOptions(ignore=ig))
    res.feed_info = {"variant": "production", "records": len(feed), "status": "cached"}
    return res


def test_text(result: AuditResult) -> None:
    out = render(result, "text", show_ignored=True)
    assert "Scanned /srv/www/site: core yes, 3 plugin(s), 1 theme(s)" in out
    assert "Feed: production (12 records, cached)" in out
    assert "CRITICAL 9.8" in out
    assert "affected <= 2.4.1; fixed in 2.4.2" in out
    assert "No known patch available." in out  # remediation used when nothing is patched
    assert "Ignored:" in out and "admin only" in out
    assert "not checked: plugin mystery" in out
    assert "warning: something else" in out
    assert "version unknown, not checked" not in out.split("not checked: plugin mystery")[1]
    assert "4 vulnerabilities in 4 component(s): 1 critical, 1 high, 2 medium" in out
    assert "(1 ignored)" in out
    assert "\033[" not in out
    # Findings are grouped: each component heading appears once.
    assert out.count("plugin example-forms 2.0.3 [") == 1


def test_text_color(result: AuditResult) -> None:
    assert "\033[1;31m" in render(result, "text", color=True)


def test_text_clean(feed: Feed) -> None:
    res = audit(feed, Inventory([Component("plugin", "safe", "1.0")]))
    out = render(res, "text")
    assert "No known vulnerabilities found." in out


def test_json(result: AuditResult) -> None:
    data = json.loads(render(result, "json"))
    assert data["schema_version"] == 1
    assert data["tool"]["name"] == "wp-vuln-audit"
    s = data["summary"]
    assert s["findings"] == 4 and s["ignored"] == 1 and s["unchecked"] == 1
    assert s["highest_severity"] == "critical"
    assert s["by_severity"] == {"critical": 1, "high": 1, "medium": 2}
    assert data["findings"][0]["id"] == vid(3)
    assert data["ignored"][0]["ignored_by"] == {"rule": "CVE-2026-20002", "reason": "admin only"}
    assert len(data["components"]) == 5
    assert data["feed"]["variant"] == "production"


def test_markdown(result: AuditResult) -> None:
    out = render(result, "markdown", show_ignored=True)
    assert out.startswith("## WordPress vulnerability audit")
    assert "| Severity | Component | Installed | Vulnerability | Fix |" in out
    assert "| Critical (9.8) | plugin `example-forms` | 2.0.3 |" in out
    assert "| Medium (6.4) | WordPress core | 6.4.2 |" in out
    assert "Update to 2.4.2" in out
    assert "<details><summary>Ignored findings</summary>" in out
    assert "Not checked (version unknown): `mystery`" in out
    assert render(result, "md") == render(result, "markdown")


def test_markdown_escapes_pipes(feed: Feed) -> None:
    rec = {
        "id": "p",
        "title": "A | B",
        "software": [{"type": "plugin", "slug": "x", "affected_versions": {"*": {}}}],
    }
    res = audit(Feed.from_data({"p": rec}), Inventory([Component("plugin", "x", "1")]))
    assert "A \\| B" in render(res, "markdown")


def test_sarif(result: AuditResult) -> None:
    doc = json.loads(render(result, "sarif"))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "wp-vuln-audit"
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) == 4
    results = run["results"]
    assert len(results) == 4
    first = results[0]
    assert first["ruleId"] == vid(3)
    assert driver["rules"][first["ruleIndex"]]["id"] == first["ruleId"]
    assert first["level"] == "error"
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "wp-content/plugins/example-forms/example-forms.php"
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    rule = driver["rules"][first["ruleIndex"]]
    assert rule["properties"]["security-severity"] == "9.8"
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]
    assert len(first["partialFingerprints"]["wpVulnAudit/v1"]) == 64
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels[vid(7)] == "warning"


def test_sarif_remote_location_and_unscored(feed: Feed) -> None:
    comp = Component("plugin", "unscored-plugin", "1.0", location="https://example.com/wp-content/plugins/u/readme.txt")
    res = audit(feed, Inventory([comp]))
    doc = json.loads(render(res, "sarif"))
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "uriBaseId" not in loc and loc["artifactLocation"]["uri"].startswith("https://")
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "5.0"


def test_sarif_empty(feed: Feed) -> None:
    doc = json.loads(render(audit(feed, Inventory()), "sarif"))
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_unknown_format(result: AuditResult) -> None:
    with pytest.raises(ValueError):
        render(result, "xml")
    assert set(FORMATS) == {"text", "json", "markdown", "sarif"}
