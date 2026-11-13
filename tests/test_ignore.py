from __future__ import annotations

import datetime as dt

import pytest

from tests.conftest import vid
from wp_vuln_audit.feed import Feed
from wp_vuln_audit.ignore import IgnoreError, IgnoreList
from wp_vuln_audit.inventory import Component

FORMS = Component("plugin", "example-forms", "2.0.3")
CORE = Component("core", "wordpress", "6.4.2")


def test_parse_all_selector_kinds() -> None:
    text = f"""
    # comment line
    {vid(3)}
    CVE-2026-20002   reason="CSRF needs an admin session"
    plugin:example-forms@2.0.3
    theme:demo-theme
    core@6.4.2       # trailing comment
    cve-2026-1234 expires=2026-12-31
    """
    rules = IgnoreList.parse(text).rules
    assert [r.kind for r in rules] == ["id", "cve", "component", "component", "core", "cve"]
    assert rules[1].reason == "CSRF needs an admin session"
    assert rules[2].version == "2.0.3" and rules[2].component_type == "plugin"
    assert rules[3].component_type == "theme" and rules[3].version is None
    assert rules[4].version == "6.4.2"
    assert rules[5].value == "CVE-2026-1234" and rules[5].expires == dt.date(2026, 12, 31)
    assert rules[0].line == 3


def test_matching(feed: Feed) -> None:
    ig = IgnoreList.parse(f"{vid(3)}\nCVE-2026-20002\n")
    assert ig.match(feed.get(vid(3)), FORMS) is not None
    assert ig.match(feed.get(vid(4)), FORMS) is not None
    assert ig.match(feed.get(vid(12)), FORMS) is None


def test_component_rules(feed: Feed) -> None:
    ig = IgnoreList.parse("plugin:example-forms@2.0.3\ncore\n")
    assert ig.match(feed.get(vid(3)), FORMS) is not None
    assert ig.match(feed.get(vid(3)), Component("plugin", "example-forms", "2.0.4")) is None
    assert ig.match(feed.get(vid(1)), CORE) is not None
    assert ig.match(feed.get(vid(3)), Component("theme", "example-forms", "2.0.3")) is None


def test_core_version_rule(feed: Feed) -> None:
    ig = IgnoreList.parse("core@6.4.1")
    assert ig.match(feed.get(vid(1)), CORE) is None
    assert ig.match(feed.get(vid(1)), Component("core", "wordpress", "6.4.1")) is not None


def test_expiry(feed: Feed) -> None:
    ig = IgnoreList.parse("CVE-2026-20001 expires=2026-06-30")
    v = feed.get(vid(3))
    assert ig.match(v, FORMS, today=dt.date(2026, 6, 30)) is not None
    assert ig.match(v, FORMS, today=dt.date(2026, 7, 1)) is None
    assert len(ig.expired(dt.date(2026, 7, 1))) == 1
    assert ig.active(dt.date(2026, 7, 1)) == []


def test_hash_inside_quotes_is_not_a_comment() -> None:
    (rule,) = IgnoreList.parse('CVE-2026-1111 reason="ticket #42"').rules
    assert rule.reason == "ticket #42"


@pytest.mark.parametrize(
    "line",
    [
        "not-a-selector!",
        "CVE-2026-1 ",
        "plugin:",
        "CVE-2026-12345 expires=tomorrow",
        "CVE-2026-12345 owner=me",
        "CVE-2026-12345 justtext",
        'CVE-2026-12345 reason="unterminated',
    ],
)
def test_errors(line: str) -> None:
    with pytest.raises(IgnoreError):
        IgnoreList.parse(line, "x.ignore")


def test_load_and_len(tmp_path) -> None:
    p = tmp_path / ".wpvulnignore"
    p.write_text("CVE-2026-20001\ncore\n", encoding="utf-8")
    ig = IgnoreList.load(p)
    assert len(ig) == 2 and ig.path == str(p)


def test_describe() -> None:
    rules = IgnoreList.parse("plugin:a@1\ncore\nCVE-2026-0001\ntheme:t").rules
    assert [r.describe() for r in rules] == ["plugin:a@1", "core", "CVE-2026-0001", "theme:t"]
