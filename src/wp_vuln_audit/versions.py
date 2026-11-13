"""Version comparison with the semantics of PHP's ``version_compare()``.

WordPress compares core, plugin and theme versions with ``version_compare()``, and the
Wordfence Intelligence feed is built for the same comparison, so this module ports the
algorithm from the PHP source (``ext/standard/versioning.c``) instead of using PEP 440
or semver rules.

The algorithm in short:

1. Canonicalise: ``-``, ``_`` and ``+`` become ``.``; a ``.`` is inserted wherever the
   string switches between digits and non-digits; any other non-alphanumeric character
   becomes ``.``. ``"4.3.2RC1"`` becomes ``"4.3.2.RC.1"``.
2. Compare the dot-separated parts left to right. Two numbers compare numerically.
   Two strings compare by their "special form" order::

       (unknown) < dev < alpha = a < beta = b < RC = rc < # < pl = p

   A number against a string is treated as ``#``, so ``1.0`` is newer than ``1.0rc1`` but
   older than ``1.0pl1``.
3. When one version runs out of parts, a remaining number makes the longer version newer
   (``1.0.1 > 1.0``, and also ``1.0.0 > 1.0``) and a remaining string is compared against
   ``#`` (``1.0 > 1.0beta``).
"""

from __future__ import annotations

import functools
import re

__all__ = [
    "canonicalize",
    "compare_versions",
    "is_valid_version",
    "normalize_version",
    "sort_versions",
    "version_key",
]

# Order of PHP's special version forms. Prefix matching mirrors PHP's strncmp() use,
# so "alpha2" never occurs (digits are split off) but "abc" counts as "a" (alpha).
_SPECIAL_FORMS: tuple[tuple[str, int], ...] = (
    ("dev", 0),
    ("alpha", 1),
    ("a", 1),
    ("beta", 2),
    ("b", 2),
    ("RC", 3),
    ("rc", 3),
    ("#", 4),
    ("pl", 5),
    ("p", 5),
)
_UNKNOWN_FORM = -6

_VALID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.\-_+]*$")


def _special_order(form: str) -> int:
    for name, order in _SPECIAL_FORMS:
        if form.startswith(name):
            return order
    return _UNKNOWN_FORM


def _compare_special(a: str, b: str) -> int:
    oa, ob = _special_order(a), _special_order(b)
    return (oa > ob) - (oa < ob)


def canonicalize(version: str) -> str:
    """Return ``version`` in PHP's canonical dotted form."""
    if not version:
        return ""
    out = [version[0]]
    prev = version[0]
    for ch in version[1:]:
        if ch in "-_+":
            if out[-1] != ".":
                out.append(".")
        elif (_is_non_digit(prev) and ch.isdigit()) or (prev.isdigit() and _is_non_digit(ch)):
            if out[-1] != ".":
                out.append(".")
            out.append(ch)
        elif not ch.isalnum():
            if out[-1] != ".":
                out.append(".")
        else:
            out.append(ch)
        prev = ch
    return "".join(out)


def _is_non_digit(ch: str) -> bool:
    return not ch.isdigit() and ch != "."


def _parts(version: str) -> list[str]:
    return [p for p in canonicalize(version).split(".") if p != ""]


def _compare_parts(a: str, b: str) -> int:
    a_digit, b_digit = a.isdigit(), b.isdigit()
    if a_digit and b_digit:
        ia, ib = int(a), int(b)
        return (ia > ib) - (ia < ib)
    if not a_digit and not b_digit:
        return _compare_special(a, b)
    if a_digit:
        return _compare_special("#N#", b)
    return _compare_special(a, "#N#")


def compare_versions(a: str, b: str) -> int:
    """Compare two version strings like PHP's ``version_compare($a, $b)``.

    Returns -1 when ``a`` is older, 0 when equal and 1 when ``a`` is newer.
    """
    a = (a or "").strip()
    b = (b or "").strip()
    if not a or not b:
        if not a and not b:
            return 0
        return -1 if not a else 1
    pa, pb = _parts(a), _parts(b)
    for x, y in zip(pa, pb, strict=False):
        result = _compare_parts(x, y)
        if result:
            return result
    if len(pa) > len(pb):
        rest = pa[len(pb)]
        return 1 if rest.isdigit() else _compare_parts(rest, "#N#")
    if len(pb) > len(pa):
        rest = pb[len(pa)]
        return -1 if rest.isdigit() else _compare_parts("#N#", rest)
    return 0


version_key = functools.cmp_to_key(compare_versions)


def sort_versions(versions: list[str]) -> list[str]:
    """Return ``versions`` sorted from oldest to newest."""
    return sorted(versions, key=version_key)


def normalize_version(version: str | None) -> str | None:
    """Clean a version string read from a header, readme or CLI output.

    Strips whitespace, quotes, a leading ``v`` (``v1.2`` -> ``1.2``) and trailing
    comments. Returns ``None`` when nothing usable is left.
    """
    if version is None:
        return None
    v = version.strip().strip("\"'").strip()
    # Drop anything after whitespace: "1.2.3 (beta)" -> "1.2.3".
    v = v.split()[0] if v.split() else ""
    if len(v) > 1 and v[0] in "vV" and v[1].isdigit():
        v = v[1:]
    v = v.rstrip(".,;")
    if not v or not _VALID_RE.match(v):
        return None
    return v


def is_valid_version(version: str | None) -> bool:
    """True when ``version`` looks like something ``version_compare()`` can order."""
    v = normalize_version(version)
    return v is not None and any(ch.isdigit() for ch in v)
