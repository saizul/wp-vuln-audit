from __future__ import annotations

import datetime as dt

import pytest

from tests.conftest import vid
from wp_vuln_audit.audit import AuditOptions, audit, check_component
from wp_vuln_audit.feed import Feed
from wp_vuln_audit.ignore import IgnoreList
from wp_vuln_audit.inventory import Component, Inventory


def inv(*components: Component) -> Inventory:
    return Inventory(list(components), target="test")


def ids(result) -> set[str]:
    return {f.vulnerability.id for f in result.findings}


def test_check_component_ranges(feed: Feed) -> None:
    found = check_component(feed, Component("plugin", "example-forms", "2.0.3"))
    assert {f.vulnerability.id for f in found} == {vid(3), vid(4)}
    by_id = {f.vulnerability.id: f for f in found}
    assert by_id[vid(4)].fixed_in == "2.0.6"
    assert by_id[vid(3)].fixed_in == "2.4.2"
    assert by_id[vid(3)].range.describe() == "<= 2.4.1"


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        (Component("core", "wordpress", "6.4.2"), {1}),
        (Component("core", "wordpress", "6.4.3"), set()),
        (Component("core", "wordpress", "6.5"), {2}),
        (Component("core", "wordpress", "6.5.3"), {2}),
        (Component("core", "wordpress", "6.5.4"), set()),
        (Component("plugin", "example-forms", "2.4.1"), {3}),
        (Component("plugin", "example-forms", "2.4.2"), set()),
        (Component("plugin", "example-forms", "3.0"), set()),  # from_inclusive false
        (Component("plugin", "example-forms", "3.0.1"), {12}),
        (Component("plugin", "example-forms", "3.1"), {12}),
        (Component("plugin", "demo-slider", "99.0"), {5}),
        (Component("plugin", "cache-helper", "1.3.0"), {6}),
        (Component("plugin", "cache-helper", "1.3.1"), set()),
        (Component("theme", "demo-theme", "1.2"), {7}),
        (Component("theme", "demo-theme", "1.4.0"), set()),  # to_inclusive false
        (Component("theme", "demo-theme", "0.9"), {10}),  # record listing two components
        (Component("plugin", "shared-lib", "1.1"), {10}),  # range parsed from the label
        (Component("plugin", "shared-lib", "1.2"), set()),
        (Component("plugin", "beta-tool", "1.0.0-RC1"), {11}),
        (Component("plugin", "beta-tool", "1.0.0"), set()),
        (Component("plugin", "beta-tool", "1.0.0-alpha"), set()),
    ],
)
def test_matching_table(feed: Feed, component: Component, expected: set[int]) -> None:
    assert {f.vulnerability.id for f in check_component(feed, component)} == {vid(n) for n in expected}


def test_unknown_version_is_unchecked(feed: Feed) -> None:
    c = Component("plugin", "example-forms", None)
    assert check_component(feed, c) == []
    result = audit(feed, inv(c))
    assert result.unchecked == [c]
    assert result.findings == []


def test_informational_hidden_by_default(feed: Feed) -> None:
    c = Component("plugin", "old-gallery", "1.0")
    assert audit(feed, inv(c)).findings == []
    assert audit(feed, inv(c)).filtered == 1
    assert ids(audit(feed, inv(c), AuditOptions(include_informational=True))) == {vid(8)}


def test_severity_filters(feed: Feed) -> None:
    components = inv(
        Component("plugin", "example-forms", "2.0.3"),  # critical 9.8 + medium 5.3
        Component("plugin", "cache-helper", "1.3.0"),  # low 3.1
        Component("plugin", "unscored-plugin", "1.0"),  # no cvss
    )
    assert ids(audit(feed, components)) == {vid(3), vid(4), vid(6), vid(9)}
    high = audit(feed, components, AuditOptions(min_severity="high"))
    assert ids(high) == {vid(3)}
    assert high.filtered == 3
    assert ids(audit(feed, components, AuditOptions(min_cvss=5.0))) == {vid(3), vid(4)}
    assert ids(audit(feed, components, AuditOptions(min_severity="high", include_unscored=True))) == {vid(3), vid(9)}
    assert vid(9) not in ids(audit(feed, components, AuditOptions(include_unscored=False)))


def test_invalid_min_severity() -> None:
    with pytest.raises(ValueError):
        AuditOptions(min_severity="severe")


def test_ignore_rules_and_expiry_warning(feed: Feed) -> None:
    ig = IgnoreList.parse('CVE-2026-20001 reason="WAF rule"\nCVE-2026-20002 expires=2026-01-01\n')
    result = audit(
        feed,
        inv(Component("plugin", "example-forms", "2.0.3")),
        AuditOptions(ignore=ig, today=dt.date(2026, 11, 13)),
    )
    assert ids(result) == {vid(4)}
    assert [f.vulnerability.id for f in result.ignored] == [vid(3)]
    assert result.ignored[0].ignored_by is not None and result.ignored[0].ignored_by.reason == "WAF rule"
    assert any("expired" in w for w in result.warnings)


def test_sorting_and_summary(feed: Feed) -> None:
    result = audit(
        feed,
        inv(
            Component("plugin", "cache-helper", "1.3.0"),
            Component("plugin", "example-forms", "2.0.3"),
            Component("core", "wordpress", "6.4.2"),
        ),
    )
    assert [f.severity for f in result.findings] == ["critical", "medium", "medium", "low"]
    # Same rating: higher score first.
    assert result.findings[1].score == 6.4
    assert result.highest() == "critical"
    assert result.counts()["medium"] == 2
    assert len(result.vulnerable_components) == 3


@pytest.mark.parametrize(
    ("threshold", "fails"),
    [("any", True), ("low", True), ("medium", True), ("high", False), ("critical", False), ("never", False)],
)
def test_fails(feed: Feed, threshold: str, fails: bool) -> None:
    result = audit(feed, inv(Component("theme", "demo-theme", "1.2")))  # medium
    assert result.fails(threshold) is fails


def test_no_findings_never_fails(feed: Feed) -> None:
    result = audit(feed, inv(Component("plugin", "safe", "1.0")))
    assert not result.fails("any")
    assert result.highest() is None


def test_finding_to_dict(feed: Feed) -> None:
    (f, *_rest) = audit(feed, inv(Component("plugin", "example-forms", "2.4.0"))).findings
    d = f.to_dict()
    assert d["id"] == vid(3)
    assert d["severity"] == "critical"
    assert d["cvss"]["score"] == 9.8
    assert d["cwe"] == {"id": 89, "name": d["cwe"]["name"]}
    assert d["fixed_in"] == "2.4.2"
    assert d["component"]["slug"] == "example-forms"
    assert d["affected_range"]["to_version"] == "2.4.1"
    assert "ignored_by" not in d


def test_duplicate_software_entries_reported_once() -> None:
    rec = {
        "id": "dup",
        "title": "dup",
        "software": [
            {"type": "plugin", "slug": "p", "affected_versions": {"* - 1.0": {}}},
            {"type": "plugin", "slug": "p", "affected_versions": {"* - 2.0": {}}},
        ],
    }
    feed = Feed.from_data({"dup": rec})
    assert len(check_component(feed, Component("plugin", "p", "0.5"))) == 1
