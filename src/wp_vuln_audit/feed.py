"""The Wordfence Intelligence vulnerability feed: records, parsing and lookup.

The v3 feed is a JSON object keyed by vulnerability id. Every value is a record such as::

    {
      "id": "0c5a...",
      "title": "Example Forms <= 2.4.1 - Unauthenticated Stored Cross-Site Scripting",
      "software": [
        {"type": "plugin", "name": "Example Forms", "slug": "example-forms",
         "affected_versions": {"* - 2.4.1": {"from_version": "*", "from_inclusive": true,
                                              "to_version": "2.4.1", "to_inclusive": true}},
         "patched": true, "patched_versions": ["2.4.2"], "remediation": "Update to 2.4.2 or newer"}
      ],
      "informational": false,
      "description": "...",
      "references": ["https://..."],
      "cwe": {"id": 79, "name": "...", "description": "..."},
      "cvss": {"vector": "CVSS:3.1/AV:N/...", "score": 7.2, "rating": "High"},
      "cve": "CVE-2026-0001", "cve_link": "https://www.cve.org/...",
      "researchers": ["..."], "published": "2026-01-02 10:00:00", "updated": "2026-01-03 10:00:00",
      "copyrights": {...}
    }

The *scanner* feed has the same layout without ``description``, ``cwe``, ``cvss``,
``cve``, ``cve_link``, ``researchers``, ``updated`` and ``remediation``. Both are handled;
missing fields become ``None`` or empty.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .ranges import VersionRange, parse_affected_versions
from .versions import compare_versions, sort_versions

__all__ = [
    "SEVERITIES",
    "Cvss",
    "Cwe",
    "Feed",
    "FeedFormatError",
    "Software",
    "Vulnerability",
    "rating_for_score",
    "severity_rank",
]

SOFTWARE_TYPES = ("core", "plugin", "theme")

# Lowest to highest. "unknown" is used for records without a CVSS score.
SEVERITIES = ("unknown", "none", "low", "medium", "high", "critical")


class FeedFormatError(ValueError):
    """The feed document does not have the expected shape."""


def severity_rank(name: str | None) -> int:
    key = (name or "unknown").strip().lower()
    return SEVERITIES.index(key) if key in SEVERITIES else 0


def rating_for_score(score: float | None) -> str:
    """CVSS v3 qualitative rating for a base score."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


@dataclass(frozen=True)
class Cvss:
    vector: str
    score: float
    rating: str

    @property
    def severity(self) -> str:
        r = (self.rating or "").strip().lower()
        return r if r in SEVERITIES else rating_for_score(self.score)


@dataclass(frozen=True)
class Cwe:
    id: int | None
    name: str
    description: str = ""


@dataclass(frozen=True)
class Software:
    type: str
    slug: str
    name: str
    ranges: tuple[VersionRange, ...]
    patched: bool = False
    patched_versions: tuple[str, ...] = ()
    remediation: str = ""

    def affects(self, version: str) -> bool:
        return any(r.contains(version) for r in self.ranges)

    def matching_range(self, version: str) -> VersionRange | None:
        for r in self.ranges:
            if r.contains(version):
                return r
        return None

    def fixed_in(self, version: str) -> str | None:
        """Smallest patched version newer than ``version`` that is itself not affected."""
        candidates = [v for v in self.patched_versions if compare_versions(v, version) > 0 and not self.affects(v)]
        if not candidates:
            return None
        return sort_versions(candidates)[0]


@dataclass(frozen=True)
class Vulnerability:
    id: str
    title: str
    software: tuple[Software, ...]
    informational: bool = False
    description: str = ""
    references: tuple[str, ...] = ()
    cve: str | None = None
    cve_link: str | None = None
    cvss: Cvss | None = None
    cwe: Cwe | None = None
    researchers: tuple[str, ...] = ()
    published: str | None = None
    updated: str | None = None

    @property
    def severity(self) -> str:
        return self.cvss.severity if self.cvss else "unknown"

    @property
    def score(self) -> float | None:
        return self.cvss.score if self.cvss else None

    @property
    def url(self) -> str:
        return f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{self.id}"


def _str(value: Any) -> str:
    return "" if value is None else str(value)


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _str_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(x) for x in value if x is not None and str(x).strip())
    if isinstance(value, str) and value.strip():
        return (value,)
    return ()


def _parse_cvss(value: Any) -> Cvss | None:
    if not isinstance(value, dict):
        return None
    raw = value.get("score")
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    return Cvss(vector=_str(value.get("vector")), score=score, rating=_str(value.get("rating")))


def _parse_cwe(value: Any) -> Cwe | None:
    if not isinstance(value, dict):
        return None
    raw = value.get("id")
    try:
        cwe_id: int | None = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        cwe_id = None
    return Cwe(id=cwe_id, name=_str(value.get("name")), description=_str(value.get("description")))


def _parse_software(value: Any) -> Software | None:
    if not isinstance(value, dict):
        return None
    stype = _str(value.get("type")).strip().lower()
    slug = _str(value.get("slug")).strip().lower()
    if stype not in SOFTWARE_TYPES or (not slug and stype != "core"):
        return None
    if stype == "core" and not slug:
        slug = "wordpress"
    return Software(
        type=stype,
        slug=slug,
        name=_str(value.get("name")) or slug,
        ranges=tuple(parse_affected_versions(value.get("affected_versions"))),
        patched=bool(value.get("patched")),
        patched_versions=_str_list(value.get("patched_versions")),
        remediation=_str(value.get("remediation")),
    )


def parse_record(key: str, record: Any) -> Vulnerability | None:
    """Turn one feed record into a :class:`Vulnerability`. Returns ``None`` if unusable."""
    if not isinstance(record, dict):
        return None
    vid = _str(record.get("id")).strip() or str(key)
    software = tuple(s for s in (_parse_software(x) for x in record.get("software") or []) if s is not None)
    if not software:
        return None
    return Vulnerability(
        id=vid,
        title=_str(record.get("title")).strip() or vid,
        software=software,
        informational=bool(record.get("informational")),
        description=_str(record.get("description")).strip(),
        references=_str_list(record.get("references")),
        cve=_opt_str(record.get("cve")),
        cve_link=_opt_str(record.get("cve_link")),
        cvss=_parse_cvss(record.get("cvss")),
        cwe=_parse_cwe(record.get("cwe")),
        researchers=_str_list(record.get("researchers")),
        published=_opt_str(record.get("published")),
        updated=_opt_str(record.get("updated")),
    )


@dataclass
class Feed:
    """An indexed set of vulnerabilities."""

    vulnerabilities: dict[str, Vulnerability] = field(default_factory=dict)
    skipped: int = 0
    _index: dict[tuple[str, str], list[tuple[Vulnerability, Software]]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not self._index:
            self._reindex()

    def _reindex(self) -> None:
        self._index = {}
        for vuln in self.vulnerabilities.values():
            for sw in vuln.software:
                self._index.setdefault((sw.type, sw.slug), []).append((vuln, sw))

    def __len__(self) -> int:
        return len(self.vulnerabilities)

    def __iter__(self) -> Iterator[Vulnerability]:
        return iter(self.vulnerabilities.values())

    def get(self, vuln_id: str) -> Vulnerability | None:
        return self.vulnerabilities.get(vuln_id)

    def for_component(self, stype: str, slug: str) -> list[tuple[Vulnerability, Software]]:
        """All (vulnerability, software entry) pairs for a component, matched or not."""
        return list(self._index.get((stype.lower(), slug.lower()), ()))

    def slugs(self, stype: str) -> set[str]:
        return {slug for (t, slug) in self._index if t == stype}

    @property
    def has_cvss(self) -> bool:
        return any(v.cvss is not None for v in self.vulnerabilities.values())

    @classmethod
    def from_records(cls, records: Iterable[Vulnerability]) -> Feed:
        return cls({v.id: v for v in records})

    @classmethod
    def from_data(cls, data: Any) -> Feed:
        """Build from a decoded feed document (dict keyed by id, or a list of records)."""
        if isinstance(data, dict):
            items: Iterable[tuple[str, Any]] = data.items()
        elif isinstance(data, list):
            items = ((str(i), r) for i, r in enumerate(data))
        else:
            raise FeedFormatError("feed must be a JSON object keyed by vulnerability id")
        vulns: dict[str, Vulnerability] = {}
        skipped = 0
        for key, record in items:
            vuln = parse_record(str(key), record)
            if vuln is None:
                skipped += 1
                continue
            vulns[vuln.id] = vuln
        feed = cls(vulns)
        feed.skipped = skipped
        return feed

    @classmethod
    def from_bytes(cls, raw: bytes) -> Feed:
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FeedFormatError(f"feed is not valid JSON: {exc}") from exc
        return cls.from_data(data)

    @classmethod
    def from_file(cls, path: str) -> Feed:
        with open(path, "rb") as fh:
            return cls.from_bytes(fh.read())
