from __future__ import annotations

import pytest

from wp_vuln_audit.versions import (
    canonicalize,
    compare_versions,
    is_valid_version,
    normalize_version,
    sort_versions,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("4.3.2RC1", "4.3.2.RC.1"),
        ("1.0-beta", "1.0.beta"),
        ("1.0_beta", "1.0.beta"),
        ("1.0+build", "1.0.build"),
        ("1.0beta2", "1.0.beta.2"),
        ("1..0", "1.0"),
        ("1.0--dev", "1.0.dev"),
        # Like PHP, a non-alphanumeric character right after a digit is kept after the dot.
        ("1.0 dev", "1.0. dev"),
        ("", ""),
        ("5", "5"),
    ],
)
def test_canonicalize(raw: str, expected: str) -> None:
    assert canonicalize(raw) == expected


# Results match PHP's version_compare().
@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0", "1.1", -1),
        ("1.10", "1.9", 1),
        ("1.0.10", "1.0.9", 1),
        ("6.4.2", "6.4.10", -1),
        ("5.2", "5.2.0", -1),
        ("1.0.0", "1.0", 1),
        ("1.0.0", "1.0.0.1", -1),
        ("1.0rc1", "1.0", -1),
        ("1.0RC1", "1.0rc1", 0),
        ("1.0", "1.0pl1", -1),
        ("1.0-dev", "1.0alpha", -1),
        ("1.0alpha", "1.0a", 0),
        ("1.0alpha", "1.0a1", -1),
        ("1.0a1", "1.0b1", -1),
        ("1.0beta", "1.0b", 0),
        ("1.0beta", "1.0b2", -1),
        ("1.0b2", "1.0RC1", -1),
        ("1.0-beta", "1.0beta", 0),
        ("1.0.0-beta", "1.0.0", -1),
        ("1.0.0", "1.0.0-beta", 1),
        ("1.0", "1.0.0-beta", -1),
        ("1.0.0", "1.0.0pl1", -1),
        ("1.0.0-foo", "1.0.0-dev", -1),
        ("1.0.0-abc", "1.0.0-alpha", 0),
        ("1.0.0-p1", "1.0.0-pl1", 0),
        ("2.0", "10.0", -1),
        ("01.2", "1.2", 0),
        ("1.2.3", "1.2.3-RC2", 1),
        ("1.0.0-beta1", "1.0.0-beta2", -1),
        ("1.0.0-rc2", "1.0.0-beta9", 1),
    ],
)
def test_compare_like_php(a: str, b: str, expected: int) -> None:
    assert compare_versions(a, b) == expected
    assert compare_versions(b, a) == -expected


def test_compare_empty() -> None:
    assert compare_versions("", "") == 0
    assert compare_versions("", "1.0") == -1
    assert compare_versions("1.0", "") == 1


def test_compare_ignores_surrounding_space() -> None:
    assert compare_versions(" 1.2 ", "1.2") == 0


def test_large_numbers() -> None:
    assert compare_versions("1.20260101", "1.20251231") == 1


def test_patch_level_sorts_after_numeric_part() -> None:
    # PHP orders "pl" above a number in the same position.
    assert compare_versions("1.0pl1", "1.0.1") == 1


def test_sort_versions() -> None:
    versions = ["1.10", "1.2", "1.0rc1", "1.0", "1.0.1", "1.0beta", "1.0-dev", "1.0pl1"]
    assert sort_versions(versions) == ["1.0-dev", "1.0beta", "1.0rc1", "1.0", "1.0.1", "1.0pl1", "1.2", "1.10"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3", "1.2.3"),
        ("  1.2.3  ", "1.2.3"),
        ("v1.2", "1.2"),
        ("V2.0.1", "2.0.1"),
        ("'1.4'", "1.4"),
        ('"1.4"', "1.4"),
        ("1.2.3 (beta)", "1.2.3"),
        ("1.2.", "1.2"),
        ("1.2-beta+3", "1.2-beta+3"),
        ("", None),
        ("   ", None),
        (None, None),
        ("<script>", None),
        ("trunk", "trunk"),
        ("vendor", "vendor"),
    ],
)
def test_normalize_version(raw: str | None, expected: str | None) -> None:
    assert normalize_version(raw) == expected


def test_is_valid_version() -> None:
    assert is_valid_version("1.0")
    assert is_valid_version("v3")
    assert not is_valid_version("trunk")
    assert not is_valid_version(None)
    assert not is_valid_version("")
