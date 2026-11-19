from __future__ import annotations

import json

from wp_vuln_audit.audit import AuditOptions, audit
from wp_vuln_audit.feed import Feed
from wp_vuln_audit.inventory import Component, Inventory
from wp_vuln_audit.report import render
from wp_vuln_audit.upgrade import plan_upgrades


def record(n: int, slug: str, low: str, high: str, patched: list[str], stype: str = "plugin") -> dict:
    return {
        "id": f"rec-{n}",
        "title": f"{slug} record {n}",
        "software": [
            {
                "type": stype,
                "slug": slug,
                "affected_versions": {
                    f"{low} - {high}": {
                        "from_version": low,
                        "from_inclusive": True,
                        "to_version": high,
                        "to_inclusive": True,
                    }
                },
                "patched": bool(patched),
                "patched_versions": patched,
            }
        ],
        "cvss": {"score": 7.5, "rating": "High", "vector": ""},
    }


def feed_of(*records: dict) -> Feed:
    return Feed.from_data({r["id"]: r for r in records})


def run(feed: Feed, *components: Component):
    return audit(feed, Inventory(list(components), target="t"), AuditOptions())


def test_plan_uses_highest_fix_per_component(feed: Feed) -> None:
    result = run(feed, Component("plugin", "example-forms", "2.0.3"), Component("core", "wordpress", "6.4.2"))
    by_slug = {u.component.slug: u for u in result.upgrades}
    forms = by_slug["example-forms"]
    assert forms.target == "2.4.2" and forms.fixes == 2 and forms.unfixed == ()
    assert forms.command == "wp plugin update example-forms --version=2.4.2"
    assert by_slug["wordpress"].command == "wp core update --version=6.4.3"
    # Same order as the findings, one entry per component.
    assert [u.component.slug for u in result.upgrades] == ["example-forms", "wordpress"]


def test_plan_without_a_fix(feed: Feed) -> None:
    (plan,) = run(feed, Component("plugin", "demo-slider", "4.2")).upgrades
    assert plan.target is None and plan.command is None
    assert plan.fixes == 0 and len(plan.unfixed) == 1


def test_target_inside_another_range_moves_up() -> None:
    feed = feed_of(
        record(1, "chain", "1.0", "1.1", ["1.2"]),
        record(2, "chain", "1.2", "1.4", ["1.5"]),  # 1.2 fixes record 1 but is itself vulnerable
        record(3, "chain", "1.5", "1.5", ["1.6"]),
    )
    (plan,) = run(feed, Component("plugin", "chain", "1.0")).upgrades
    assert plan.target == "1.6" and plan.fixes == 1 and plan.still_affected == ()


def test_target_still_affected_by_unfixed_advisory() -> None:
    feed = feed_of(
        record(1, "partial", "1.0", "1.1", ["1.2"]),
        record(2, "partial", "1.2", "9.9", []),
    )
    (plan,) = run(feed, Component("theme", "partial", "1.0", status=""), Component("plugin", "partial", "1.0")).upgrades
    assert plan.component.type == "plugin"
    assert plan.target == "1.2" and plan.still_affected == ("rec-2",)


def test_must_use_plugins_get_no_command() -> None:
    feed = feed_of(record(1, "mu-tool", "1.0", "1.0", ["1.1"]))
    (plan,) = plan_upgrades(feed, run(feed, Component("plugin", "mu-tool", "1.0", status="must-use")).findings)
    assert plan.target == "1.1" and plan.command is None


def test_reports_show_the_plan(feed: Feed) -> None:
    result = run(feed, Component("plugin", "example-forms", "2.0.3"), Component("plugin", "demo-slider", "4.2"))
    text = render(result, "text")
    assert "Upgrade plan:" in text
    assert "plugin example-forms 2.0.3 -> 2.4.2 (fixes 2): wp plugin update example-forms --version=2.4.2" in text
    assert "plugin demo-slider 4.2: no fixed version" in text
    md = render(result, "markdown")
    assert "### Upgrade plan" in md and "`wp plugin update example-forms --version=2.4.2`" in md
    data = json.loads(render(result, "json"))
    assert data["upgrades"][0] == {
        "type": "plugin",
        "slug": "example-forms",
        "installed": "2.0.3",
        "target": "2.4.2",
        "fixes": 2,
        "unfixed": [],
        "still_affected": [],
        "command": "wp plugin update example-forms --version=2.4.2",
    }
    assert data["upgrades"][1]["target"] is None


def test_no_findings_no_plan(feed: Feed) -> None:
    result = run(feed, Component("core", "wordpress", "6.4.3"))
    assert result.upgrades == []
    assert "Upgrade plan" not in render(result, "text")
    assert json.loads(render(result, "json"))["upgrades"] == []
