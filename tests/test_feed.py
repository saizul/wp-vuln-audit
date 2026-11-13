from __future__ import annotations

import json

import pytest

from tests.conftest import vid
from wp_vuln_audit.feed import Feed, FeedFormatError, parse_record, rating_for_score, severity_rank


def test_loads_production_fixture(feed: Feed) -> None:
    assert len(feed) == 12
    assert feed.skipped == 1  # the record without software
    assert feed.has_cvss


def test_record_fields(feed: Feed) -> None:
    v = feed.get(vid(3))
    assert v is not None
    assert v.title.startswith("Example Forms <= 2.4.1")
    assert v.cve == "CVE-2026-20001"
    assert v.cvss is not None and v.cvss.score == 9.8 and v.severity == "critical"
    assert v.cwe is not None and v.cwe.id == 89
    assert v.references == ("https://example.com/advisory/3",)
    assert v.researchers == ("Fixture Researcher",)
    assert v.url == f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{vid(3)}"
    (sw,) = v.software
    assert sw.type == "plugin" and sw.slug == "example-forms" and sw.patched
    assert sw.patched_versions == ("2.4.2",)
    assert sw.remediation.startswith("Update to version 2.4.2")


def test_scanner_feed_has_no_cvss(scanner_feed: Feed) -> None:
    assert len(scanner_feed) == 7
    assert not scanner_feed.has_cvss
    v = scanner_feed.get(vid(1))
    assert v is not None and v.cvss is None and v.severity == "unknown" and v.cve is None


def test_for_component_index(feed: Feed) -> None:
    pairs = feed.for_component("plugin", "example-forms")
    assert {v.id for v, _ in pairs} == {vid(3), vid(4), vid(12)}
    assert feed.for_component("PLUGIN", "Example-Forms") == pairs
    assert feed.for_component("plugin", "missing") == []
    # A record can list several pieces of software.
    assert vid(10) in {v.id for v, _ in feed.for_component("theme", "demo-theme")}
    assert "example-forms" in feed.slugs("plugin")


def test_fixed_in(feed: Feed) -> None:
    sw = feed.get(vid(4)).software[0]  # 2.0.0 - 2.0.5, patched in 2.0.6 and 2.4.2
    assert sw.fixed_in("2.0.3") == "2.0.6"
    sw3 = feed.get(vid(3)).software[0]
    assert sw3.fixed_in("2.0.3") == "2.4.2"
    sw5 = feed.get(vid(5)).software[0]
    assert sw5.fixed_in("4.2") is None


def test_fixed_in_skips_patched_versions_that_are_still_affected() -> None:
    record = {
        "id": "x",
        "title": "t",
        "software": [
            {
                "type": "plugin",
                "slug": "p",
                "affected_versions": {
                    "* - 2.0": {"from_version": "*", "from_inclusive": True, "to_version": "2.0", "to_inclusive": True}
                },
                "patched": True,
                "patched_versions": ["1.5", "2.0", "2.1"],
            }
        ],
    }
    v = parse_record("x", record)
    assert v is not None and v.software[0].fixed_in("1.0") == "2.1"


def test_core_slug_defaults_to_wordpress() -> None:
    v = parse_record("c", {"id": "c", "title": "core", "software": [{"type": "core", "affected_versions": {"*": {}}}]})
    assert v is not None and v.software[0].slug == "wordpress"


@pytest.mark.parametrize(
    "record",
    [
        None,
        "string",
        {"id": "a", "title": "t", "software": []},
        {"id": "a", "title": "t", "software": [{"type": "mu-plugin", "slug": "x"}]},
        {"id": "a", "title": "t", "software": [{"type": "plugin", "slug": ""}]},
        {"id": "a", "title": "t"},
    ],
)
def test_unusable_records(record: object) -> None:
    assert parse_record("a", record) is None


def test_bad_cvss_and_cwe_are_dropped() -> None:
    v = parse_record(
        "a",
        {
            "id": "a",
            "title": "t",
            "software": [{"type": "plugin", "slug": "s", "affected_versions": {"*": {}}}],
            "cvss": {"score": "n/a", "vector": "", "rating": ""},
            "cwe": {"id": "CWE-79", "name": "XSS"},
            "references": "https://example.com/one",
        },
    )
    assert v is not None
    assert v.cvss is None
    assert v.cwe is not None and v.cwe.id is None and v.cwe.name == "XSS"
    assert v.references == ("https://example.com/one",)


def test_id_falls_back_to_key_and_title_to_id() -> None:
    v = parse_record("key-1", {"software": [{"type": "theme", "slug": "t", "affected_versions": {}}]})
    assert v is not None and v.id == "key-1" and v.title == "key-1"


def test_from_bytes_errors() -> None:
    with pytest.raises(FeedFormatError):
        Feed.from_bytes(b"not json")
    with pytest.raises(FeedFormatError):
        Feed.from_bytes(b'"a string"')
    with pytest.raises(FeedFormatError):
        Feed.from_bytes(b"\xff\xfe")


def test_from_bytes_accepts_bom_and_list() -> None:
    rec = {"id": "a", "title": "t", "software": [{"type": "plugin", "slug": "s", "affected_versions": {"*": {}}}]}
    assert len(Feed.from_bytes(b"\xef\xbb\xbf" + json.dumps({"a": rec}).encode())) == 1
    assert len(Feed.from_bytes(json.dumps([rec]).encode())) == 1


def test_iteration_and_from_records(feed: Feed) -> None:
    clone = Feed.from_records(list(feed))
    assert len(clone) == len(feed)
    assert clone.for_component("plugin", "example-forms")


@pytest.mark.parametrize(
    ("score", "rating"),
    [
        (None, "unknown"),
        (0.0, "none"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (9.0, "critical"),
    ],
)
def test_rating_for_score(score: float | None, rating: str) -> None:
    assert rating_for_score(score) == rating


def test_severity_rank() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("medium") > severity_rank("low")
    assert severity_rank("bogus") == severity_rank("unknown") == 0
    assert severity_rank(None) == 0


def test_cvss_rating_fallback_to_score() -> None:
    v = parse_record(
        "a",
        {
            "id": "a",
            "title": "t",
            "software": [{"type": "plugin", "slug": "s", "affected_versions": {"*": {}}}],
            "cvss": {"score": 7.3, "vector": "v", "rating": "Severe"},
        },
    )
    assert v is not None and v.severity == "high"
