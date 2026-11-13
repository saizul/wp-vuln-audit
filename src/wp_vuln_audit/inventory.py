"""Installed software: the components a scan checks against the feed."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["Component", "Inventory"]


@dataclass(frozen=True)
class Component:
    """One installed piece of software.

    ``type`` is ``core``, ``plugin`` or ``theme``. ``slug`` is the WordPress.org slug (the
    directory name for plugins and themes, ``wordpress`` for core). ``version`` is
    ``None`` when it could not be determined. ``location`` is the file the version was read
    from, relative to the scanned root or a URL, and ``source`` says how it was found
    (``local``, ``wp-cli`` or ``remote``).
    """

    type: str
    slug: str
    version: str | None
    name: str = ""
    location: str = ""
    source: str = "local"
    status: str = ""
    notes: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.slug)

    @property
    def label(self) -> str:
        if self.type == "core":
            return f"WordPress {self.version or '?'}"
        return f"{self.type} {self.slug} {self.version or '?'}"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "type": self.type,
            "slug": self.slug,
            "name": self.name or self.slug,
            "version": self.version,
            "location": self.location,
            "source": self.source,
        }
        if self.status:
            data["status"] = self.status
        if self.notes:
            data["notes"] = list(self.notes)
        return data


@dataclass
class Inventory:
    components: list[Component] = field(default_factory=list)
    target: str = ""
    warnings: list[str] = field(default_factory=list)

    def add(self, component: Component) -> None:
        """Add a component, replacing an earlier one with the same type and slug."""
        for i, existing in enumerate(self.components):
            if existing.key == component.key:
                # Prefer the entry that knows its version.
                if existing.version and not component.version:
                    return
                self.components[i] = component
                return
        self.components.append(component)

    def extend(self, other: Inventory) -> None:
        for c in other.components:
            self.add(c)
        self.warnings.extend(other.warnings)

    @property
    def core(self) -> Component | None:
        for c in self.components:
            if c.type == "core":
                return c
        return None

    def by_type(self, stype: str) -> list[Component]:
        return [c for c in self.components if c.type == stype]

    def counts(self) -> dict[str, int]:
        out = {"core": 0, "plugin": 0, "theme": 0}
        for c in self.components:
            out[c.type] = out.get(c.type, 0) + 1
        return out

    def __len__(self) -> int:
        return len(self.components)
