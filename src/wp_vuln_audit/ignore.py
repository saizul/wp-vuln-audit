"""The ignore file (``.wpvulnignore``).

One rule per line; ``#`` starts a comment. A rule is a selector followed by optional
``key=value`` options::

    # A Wordfence vulnerability id or a CVE
    0c5a1e2f-1111-4c3d-9e8f-000000000001
    CVE-2026-0002              reason="admin-only, plugin disabled on this site"

    # Every vulnerability of a component, or of one installed version of it
    plugin:example-forms
    theme:demo-theme@1.4.0
    core

    # Rules can expire; after the date the rule is ignored and a warning is printed
    CVE-2026-0003 expires=2026-12-31 reason="vendor fix scheduled"

Values with spaces go in double quotes.
"""

from __future__ import annotations

import datetime as _dt
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .feed import Vulnerability
from .inventory import Component
from .versions import compare_versions

__all__ = ["IgnoreError", "IgnoreList", "IgnoreRule", "DEFAULT_IGNORE_FILE"]

DEFAULT_IGNORE_FILE = ".wpvulnignore"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_COMPONENT_RE = re.compile(r"^(plugin|theme):([a-z0-9][a-z0-9._-]*)(?:@(\S+))?$", re.IGNORECASE)
_ID_RE = re.compile(r"^[0-9a-f][0-9a-f-]{7,}$", re.IGNORECASE)


class IgnoreError(ValueError):
    """A line of the ignore file is invalid."""


@dataclass(frozen=True)
class IgnoreRule:
    kind: str  # "id", "cve", "component", "core"
    value: str
    component_type: str = ""
    version: str | None = None
    expires: _dt.date | None = None
    reason: str = ""
    line: int = 0

    def expired(self, today: _dt.date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, vuln: Vulnerability, component: Component) -> bool:
        if self.kind == "id":
            return vuln.id.lower() == self.value
        if self.kind == "cve":
            return (vuln.cve or "").upper() == self.value
        if self.kind == "core":
            return component.type == "core" and (
                self.version is None or compare_versions(component.version or "", self.version) == 0
            )
        if component.type != self.component_type or component.slug != self.value:
            return False
        return self.version is None or compare_versions(component.version or "", self.version) == 0

    def describe(self) -> str:
        if self.kind in ("id", "cve"):
            return self.value
        if self.kind == "core":
            return "core" + (f"@{self.version}" if self.version else "")
        return f"{self.component_type}:{self.value}" + (f"@{self.version}" if self.version else "")


@dataclass
class IgnoreList:
    rules: list[IgnoreRule] = field(default_factory=list)
    path: str = ""

    @classmethod
    def parse(cls, text: str, path: str = "") -> IgnoreList:
        rules: list[IgnoreRule] = []
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw).strip()
            if not line:
                continue
            try:
                tokens = shlex.split(line, posix=True)
            except ValueError as exc:
                raise IgnoreError(f"{path or 'ignore file'}:{lineno}: {exc}") from exc
            rules.append(_parse_rule(tokens, lineno, path))
        return cls(rules, path)

    @classmethod
    def load(cls, path: str | Path) -> IgnoreList:
        p = Path(path)
        return cls.parse(p.read_text(encoding="utf-8"), str(p))

    def active(self, today: _dt.date | None = None) -> list[IgnoreRule]:
        day = today or _dt.date.today()
        return [r for r in self.rules if not r.expired(day)]

    def expired(self, today: _dt.date | None = None) -> list[IgnoreRule]:
        day = today or _dt.date.today()
        return [r for r in self.rules if r.expired(day)]

    def match(self, vuln: Vulnerability, component: Component, today: _dt.date | None = None) -> IgnoreRule | None:
        for rule in self.active(today):
            if rule.matches(vuln, component):
                return rule
        return None

    def __len__(self) -> int:
        return len(self.rules)


def _strip_comment(line: str) -> str:
    out = []
    quoted = False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            break
        out.append(ch)
    return "".join(out)


def _parse_rule(tokens: list[str], lineno: int, path: str) -> IgnoreRule:
    where = f"{path or 'ignore file'}:{lineno}"
    selector, options = tokens[0], tokens[1:]
    expires: _dt.date | None = None
    reason = ""
    for opt in options:
        if "=" not in opt:
            raise IgnoreError(f"{where}: expected key=value, got {opt!r}")
        key, value = opt.split("=", 1)
        key = key.strip().lower()
        if key == "expires":
            try:
                expires = _dt.date.fromisoformat(value.strip())
            except ValueError as exc:
                raise IgnoreError(f"{where}: expires must be YYYY-MM-DD, got {value!r}") from exc
        elif key == "reason":
            reason = value
        else:
            raise IgnoreError(f"{where}: unknown option {key!r}")

    if _CVE_RE.match(selector):
        return IgnoreRule("cve", selector.upper(), expires=expires, reason=reason, line=lineno)
    low = selector.lower()
    if low == "core" or low.startswith("core@"):
        version = selector.split("@", 1)[1] if "@" in selector else None
        return IgnoreRule("core", "wordpress", "core", version, expires, reason, lineno)
    m = _COMPONENT_RE.match(selector)
    if m:
        return IgnoreRule("component", m.group(2).lower(), m.group(1).lower(), m.group(3), expires, reason, lineno)
    if _ID_RE.match(selector):
        return IgnoreRule("id", low, expires=expires, reason=reason, line=lineno)
    raise IgnoreError(f"{where}: unrecognised selector {selector!r}")
