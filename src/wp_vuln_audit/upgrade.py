"""Upgrade plan: the lowest version per component that fixes every reported vulnerability."""

from __future__ import annotations

import dataclasses
import functools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .versions import compare_versions

if TYPE_CHECKING:
    from .audit import Finding
    from .feed import Feed
    from .inventory import Component

__all__ = ["Upgrade", "plan_upgrades"]

# A fixed version can itself be inside another advisory's range; follow at most this many hops.
MAX_STEPS = 10

_version_key = functools.cmp_to_key(compare_versions)


@dataclass(frozen=True)
class Upgrade:
    """What to do about one vulnerable component.

    ``target`` is the version to update to, or ``None`` when no reported vulnerability has a fixed version.
    ``fixes`` counts the reported findings that ``target`` fixes; ``unfixed`` holds the ones without a fix (the
    component still needs to be replaced, removed or protected after the update). ``still_affected`` is set when
    ``target`` is inside the range of another advisory that has no fix yet.
    """

    component: Component
    target: str | None
    fixes: int
    unfixed: tuple[Finding, ...] = ()
    still_affected: tuple[str, ...] = ()

    @property
    def command(self) -> str | None:
        """The WP-CLI command that performs the update, when there is a target and WP-CLI can do it."""
        if self.target is None or self.component.status == "must-use":
            return None
        if self.component.type == "core":
            return f"wp core update --version={self.target}"
        return f"wp {self.component.type} update {self.component.slug} --version={self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.component.type,
            "slug": self.component.slug,
            "installed": self.component.version,
            "target": self.target,
            "fixes": self.fixes,
            "unfixed": [f.vulnerability.id for f in self.unfixed],
            "still_affected": list(self.still_affected),
            "command": self.command,
        }


def _fixed_versions(findings: list[Finding]) -> list[str]:
    return [f.fixed_in for f in findings if f.fixed_in]


def plan_upgrades(feed: Feed, findings: list[Finding]) -> list[Upgrade]:
    """One :class:`Upgrade` per component with findings, in the order of the findings.

    The target starts as the highest "fixed in" version of the component's findings. It is then checked against
    every record in the feed for the component: when it is inside another fixable range, the target moves up to that
    fix, so the plan never suggests a version with a known, fixable vulnerability.
    """
    from .audit import check_component

    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.component.key, []).append(f)
    plans: list[Upgrade] = []
    for group in groups.values():
        comp = group[0].component
        unfixed = tuple(f for f in group if not f.fixed_in)
        fixed = _fixed_versions(group)
        target = max(fixed, key=_version_key) if fixed else None
        still: tuple[str, ...] = ()
        if target is not None:
            for _ in range(MAX_STEPS):
                remaining = check_component(feed, dataclasses.replace(comp, version=target))
                bumps = [v for v in _fixed_versions(remaining) if compare_versions(v, target) > 0]
                if not bumps:
                    still = tuple(r.vulnerability.id for r in remaining)
                    break
                target = max(bumps, key=_version_key)
        plans.append(Upgrade(comp, target, len(group) - len(unfixed), unfixed, still))
    return plans
