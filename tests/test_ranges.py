from __future__ import annotations

import pytest

from wp_vuln_audit.ranges import ANY, RangeError, VersionRange, parse_affected_versions, parse_range_label


def test_unbounded_range_contains_everything() -> None:
    r = VersionRange()
    assert r.unbounded
    assert r.contains("0.1")
    assert r.contains("99.0")
    assert r.describe() == "all versions"


@pytest.mark.parametrize(
    ("rng", "version", "expected"),
    [
        (VersionRange(ANY, True, "2.4.1", True), "2.4.1", True),
        (VersionRange(ANY, True, "2.4.1", True), "2.4.2", False),
        (VersionRange(ANY, True, "2.4.1", False), "2.4.1", False),
        (VersionRange(ANY, True, "2.4.1", False), "2.4.0", True),
        (VersionRange("2.0", True, ANY, True), "2.0", True),
        (VersionRange("2.0", False, ANY, True), "2.0", False),
        (VersionRange("2.0", False, ANY, True), "2.0.1", True),
        (VersionRange("2.0", True, "2.5", True), "1.9", False),
        (VersionRange("2.0", True, "2.5", True), "2.10", False),
        (VersionRange("2.0", True, "2.5", True), "2.4.9", True),
        (VersionRange("1.3.0", True, "1.3.0", True), "1.3.0", True),
        (VersionRange("1.3.0", True, "1.3.0", True), "1.3", False),
        (VersionRange("1.0.0-beta1", True, "1.0.0", False), "1.0.0-RC2", True),
        (VersionRange("1.0.0-beta1", True, "1.0.0", False), "1.0.0-alpha", False),
        (VersionRange("1.0.0-beta1", True, "1.0.0", False), "1.0.0", False),
    ],
)
def test_contains(rng: VersionRange, version: str, expected: bool) -> None:
    assert rng.contains(version) is expected


def test_describe() -> None:
    assert VersionRange(ANY, True, "1.2", True).describe() == "<= 1.2"
    assert VersionRange(ANY, True, "1.2", False).describe() == "< 1.2"
    assert VersionRange("1.0", True, "1.2", False).describe() == ">= 1.0, < 1.2"
    assert VersionRange("1.0", False, ANY, True).describe() == "> 1.0"
    assert VersionRange("1.3", True, "1.3", True).describe() == "= 1.3"


@pytest.mark.parametrize(
    ("label", "lo", "lo_inc", "hi", "hi_inc"),
    [
        ("* - 1.2.3", ANY, True, "1.2.3", True),
        ("1.0 - 1.2.3", "1.0", True, "1.2.3", True),
        ("1.2.3", "1.2.3", True, "1.2.3", True),
        ("<= 1.2", ANY, True, "1.2", True),
        ("< 1.2", ANY, True, "1.2", False),
        (">= 1.0", "1.0", True, ANY, True),
        ("> 1.0", "1.0", False, ANY, True),
        ("= 1.0", "1.0", True, "1.0", True),
        ("<=1.2", ANY, True, "1.2", True),
        ("*", ANY, True, ANY, True),
        ("1.0.0-beta1 - 1.0.0-RC2", "1.0.0-beta1", True, "1.0.0-RC2", True),
    ],
)
def test_parse_range_label(label: str, lo: str, lo_inc: bool, hi: str, hi_inc: bool) -> None:
    r = parse_range_label(label)
    assert (r.from_version, r.from_inclusive, r.to_version, r.to_inclusive) == (lo, lo_inc, hi, hi_inc)


@pytest.mark.parametrize("label", ["", "   ", "from 1 to 2", "1.0 -"])
def test_parse_range_label_errors(label: str) -> None:
    with pytest.raises(RangeError):
        parse_range_label(label)


def test_parse_affected_versions_dict_values_win_over_labels() -> None:
    data = {
        "* - 5.3.1": {"from_version": "*", "from_inclusive": True, "to_version": "5.3.1", "to_inclusive": True},
        # Label says inclusive, the value says exclusive: the value is authoritative.
        "6.0 - 6.0.2": {"from_version": "6.0", "from_inclusive": True, "to_version": "6.0.2", "to_inclusive": False},
    }
    ranges = parse_affected_versions(data)
    assert len(ranges) == 2
    assert ranges[1].contains("6.0.1")
    assert not ranges[1].contains("6.0.2")
    assert ranges[0].label == "* - 5.3.1"


def test_parse_affected_versions_falls_back_to_label() -> None:
    ranges = parse_affected_versions({"<= 1.1": {}, "2.0": None, "garbage label here": {}})
    assert len(ranges) == 2
    assert ranges[0].contains("1.1") and not ranges[0].contains("1.2")
    assert ranges[1].contains("2.0") and not ranges[1].contains("2.0.1")


def test_parse_affected_versions_string_bool_and_null_bounds() -> None:
    data = {"x": {"from_version": None, "from_inclusive": "true", "to_version": "", "to_inclusive": 0}}
    (r,) = parse_affected_versions(data)
    assert r.unbounded


def test_parse_affected_versions_string_values_and_lists() -> None:
    assert parse_affected_versions({"a": "< 2.0"})[0].to_version == "2.0"
    assert len(parse_affected_versions(["<= 1.0", "2.0 - 2.1"])) == 2
    assert len(parse_affected_versions("* - 1.0")) == 1
    assert parse_affected_versions(None) == []
    assert parse_affected_versions(42) == []


def test_to_dict_round_trip() -> None:
    r = VersionRange("1.0", False, "2.0", True)
    assert r.to_dict() == {"from_version": "1.0", "from_inclusive": False, "to_version": "2.0", "to_inclusive": True}
