"""Affected-version ranges as published in the Wordfence Intelligence feed.

Each software entry of a feed record has an ``affected_versions`` object. Its keys are
human-readable labels and its values carry the actual bounds::

    "affected_versions": {
        "* - 5.3.1": {
            "from_version": "*", "from_inclusive": true,
            "to_version": "5.3.1", "to_inclusive": true
        },
        "6.0 - 6.0.2": {
            "from_version": "6.0", "from_inclusive": true,
            "to_version": "6.0.2", "to_inclusive": false
        }
    }

``"*"`` as a bound means "no bound on this side". A single affected version has the same
value in ``from_version`` and ``to_version`` with both ends inclusive.

When a value is missing or malformed the label itself is parsed, so the following forms
are also understood: ``"* - 1.2"``, ``"1.0 - 1.2"``, ``"1.2"``, ``"<= 1.2"``, ``"< 1.2"``,
``">= 1.0"``, ``"> 1.0"`` and ``"*"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .versions import compare_versions

__all__ = ["ANY", "RangeError", "VersionRange", "parse_affected_versions", "parse_range_label"]

ANY = "*"


class RangeError(ValueError):
    """Raised when a range can not be understood."""


@dataclass(frozen=True)
class VersionRange:
    from_version: str = ANY
    from_inclusive: bool = True
    to_version: str = ANY
    to_inclusive: bool = True
    label: str = ""

    def contains(self, version: str) -> bool:
        """True when ``version`` falls inside this range."""
        if self.from_version != ANY:
            c = compare_versions(version, self.from_version)
            if c < 0 or (c == 0 and not self.from_inclusive):
                return False
        if self.to_version != ANY:
            c = compare_versions(version, self.to_version)
            if c > 0 or (c == 0 and not self.to_inclusive):
                return False
        return True

    @property
    def unbounded(self) -> bool:
        return self.from_version == ANY and self.to_version == ANY

    def describe(self) -> str:
        """Readable form, for example ``>= 1.0, < 1.4.2`` or ``all versions``."""
        if self.unbounded:
            return "all versions"
        if self.from_version == self.to_version and self.from_inclusive and self.to_inclusive:
            return f"= {self.from_version}"
        parts = []
        if self.from_version != ANY:
            parts.append(f"{'>=' if self.from_inclusive else '>'} {self.from_version}")
        if self.to_version != ANY:
            parts.append(f"{'<=' if self.to_inclusive else '<'} {self.to_version}")
        return ", ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_version": self.from_version,
            "from_inclusive": self.from_inclusive,
            "to_version": self.to_version,
            "to_inclusive": self.to_inclusive,
        }


_DASH_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")
_OP_RE = re.compile(r"^\s*(<=|>=|<|>|=|==)\s*(\S+)\s*$")


def parse_range_label(label: str) -> VersionRange:
    """Parse a range written as text, such as ``"* - 1.2.3"`` or ``"< 2.0"``."""
    text = (label or "").strip()
    if not text:
        raise RangeError("empty range")
    if text == ANY:
        return VersionRange(label=label)
    m = _DASH_RE.match(text)
    if m:
        lo, hi = m.group(1), m.group(2)
        return VersionRange(lo, True, hi, True, label=label)
    m = _OP_RE.match(text)
    if m:
        op, v = m.group(1), m.group(2)
        if op == "<=":
            return VersionRange(ANY, True, v, True, label=label)
        if op == "<":
            return VersionRange(ANY, True, v, False, label=label)
        if op == ">=":
            return VersionRange(v, True, ANY, True, label=label)
        if op == ">":
            return VersionRange(v, False, ANY, True, label=label)
        return VersionRange(v, True, v, True, label=label)
    if " " not in text:
        return VersionRange(text, True, text, True, label=label)
    raise RangeError(f"unrecognised range {label!r}")


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return default


def _bound(value: Any) -> str:
    if value is None:
        return ANY
    text = str(value).strip()
    return text or ANY


def parse_range_value(label: str, value: Any) -> VersionRange:
    """Build a range from one ``affected_versions`` entry."""
    if isinstance(value, dict) and ("from_version" in value or "to_version" in value):
        return VersionRange(
            from_version=_bound(value.get("from_version")),
            from_inclusive=_as_bool(value.get("from_inclusive"), True),
            to_version=_bound(value.get("to_version")),
            to_inclusive=_as_bool(value.get("to_inclusive"), True),
            label=label,
        )
    if isinstance(value, str) and value.strip():
        return parse_range_label(value)
    return parse_range_label(label)


def parse_affected_versions(data: Any) -> list[VersionRange]:
    """Parse an ``affected_versions`` object (or a list of labels) into ranges.

    Entries that can not be understood are skipped; callers that need to know can compare
    the input size with the result.
    """
    ranges: list[VersionRange] = []
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = [(str(x) if not isinstance(x, dict) else "", x) for x in data]
    elif isinstance(data, str):
        items = [(data, None)]
    else:
        return ranges
    for label, value in items:
        try:
            ranges.append(parse_range_value(str(label), value))
        except RangeError:
            continue
    return ranges
