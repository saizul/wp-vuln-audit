"""Reading WP-CLI output.

Supported inputs:

* ``wp plugin list --format=json`` and ``wp theme list --format=json``: a JSON array of
  objects with ``name``, ``status``, ``version`` and usually ``update`` and
  ``update_version``.
* ``wp core version``: a bare version string, or ``--extra`` output with a
  ``WordPress version:`` line.
* A combined document ``{"core": "6.6.2", "plugins": [...], "themes": [...]}``, handy when
  a CI job collects everything in one step.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .inventory import Component, Inventory
from .versions import normalize_version

__all__ = ["WpCliError", "parse_core_version", "parse_list", "parse_combined"]


class WpCliError(ValueError):
    """The WP-CLI output could not be parsed."""


def _load(text: str) -> Any:
    text = text.strip()
    if not text:
        raise WpCliError("empty WP-CLI output")
    # WP-CLI may print PHP notices or "Success:" lines before the JSON; start at the first bracket.
    start = min((i for i in (text.find("["), text.find("{")) if i >= 0), default=-1)
    if start < 0:
        raise WpCliError("no JSON found in WP-CLI output")
    try:
        return json.JSONDecoder().raw_decode(text[start:])[0]
    except json.JSONDecodeError as exc:
        raise WpCliError(f"invalid JSON in WP-CLI output: {exc}") from exc


def _components(items: Any, stype: str, location: str) -> list[Component]:
    if not isinstance(items, list):
        raise WpCliError(f"expected a JSON array for {stype}s")
    out: list[Component] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        slug = str(item.get("name") or item.get("slug") or "").strip().lower()
        if not slug:
            continue
        status = str(item.get("status") or "")
        # Drop-ins and must-use plugins have no WordPress.org slug of their own.
        if stype == "plugin" and status == "dropin":
            continue
        version = normalize_version(str(item["version"])) if item.get("version") not in (None, "") else None
        notes: list[str] = []
        update_version = item.get("update_version")
        if item.get("update") == "available" and update_version:
            notes.append(f"update available: {update_version}")
        if version is None:
            notes.append("no version reported")
        out.append(
            Component(
                type=stype,
                slug=slug,
                version=version,
                name=str(item.get("title") or slug),
                location=location,
                source="wp-cli",
                status=status,
                notes=tuple(notes),
            )
        )
    return out


def parse_list(text: str, stype: str, location: str = "wp-cli") -> list[Component]:
    """Parse ``wp plugin list`` or ``wp theme list`` JSON."""
    if stype not in ("plugin", "theme"):
        raise ValueError("stype must be 'plugin' or 'theme'")
    return _components(_load(text), stype, location)


_CORE_EXTRA_RE = re.compile(r"WordPress version:\s*(\S+)", re.IGNORECASE)


def parse_core_version(text: str) -> str | None:
    """Parse ``wp core version`` (optionally with ``--extra``)."""
    m = _CORE_EXTRA_RE.search(text)
    raw = m.group(1) if m else text.strip().splitlines()[0] if text.strip() else ""
    return normalize_version(raw)


def parse_combined(text: str, location: str = "wp-cli") -> Inventory:
    """Parse a combined ``{"core": ..., "plugins": [...], "themes": [...]}`` document.

    A bare array is accepted too and read as a plugin list.
    """
    data = _load(text)
    inv = Inventory(target=location)
    if isinstance(data, list):
        for c in _components(data, "plugin", location):
            inv.add(c)
        return inv
    if not isinstance(data, dict):
        raise WpCliError("expected a JSON object or array")
    core = data.get("core")
    if isinstance(core, dict):
        core = core.get("version")
    if core:
        version = normalize_version(str(core))
        if version:
            inv.add(Component("core", "wordpress", version, "WordPress", location, source="wp-cli"))
    for key, stype in (("plugins", "plugin"), ("themes", "theme")):
        if key in data:
            for c in _components(data[key], stype, location):
                inv.add(c)
    return inv
