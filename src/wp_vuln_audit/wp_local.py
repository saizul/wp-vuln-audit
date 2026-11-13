"""Reading versions from a WordPress install on disk.

* Core: ``$wp_version`` in ``wp-includes/version.php``.
* Plugins: every directory in ``wp-content/plugins`` whose PHP files (top level only, as
  WordPress does) contain a ``Plugin Name:`` header; single-file plugins in the plugins
  directory itself; and, with ``include_mu``, files in ``wp-content/mu-plugins``.
* Themes: ``style.css`` in every directory of ``wp-content/themes`` with a ``Theme Name:``
  header.

Headers are read the way WordPress' ``get_file_data()`` reads them: only the first 8 KiB
of the file, one header per line, with leading comment characters ignored. No PHP is
executed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .inventory import Component, Inventory
from .versions import normalize_version

__all__ = [
    "WordPressNotFound",
    "find_content_dir",
    "read_core_version",
    "read_file_headers",
    "scan_local",
    "scan_plugins",
    "scan_themes",
]

HEADER_BYTES = 8192

# Single-file plugins whose WordPress.org slug differs from the file name.
SINGLE_FILE_SLUGS = {"hello.php": "hello-dolly"}

_VERSION_PHP_RE = re.compile(r"""\$wp_version\s*=\s*(['"])([^'"]+)\1\s*;""")


class WordPressNotFound(FileNotFoundError):
    """The path does not look like a WordPress install."""


def read_file_headers(path: Path, names: tuple[str, ...]) -> dict[str, str]:
    """Read WordPress file headers (``Name: value`` lines) from the start of ``path``."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(HEADER_BYTES)
    except OSError:
        return {}
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    found: dict[str, str] = {}
    for name in names:
        m = re.search(r"^(?:[ \t]*<\?php)?[ \t/*#@]*" + re.escape(name) + r":(.*)$", text, re.MULTILINE | re.IGNORECASE)
        if m:
            # _cleanup_header_comment(): drop a trailing "*/" or "?>" and surrounding space.
            value = re.sub(r"\s*(?:\*/|\?>).*", "", m.group(1)).strip()
            if value:
                found[name] = value
    return found


def read_core_version(root: Path) -> str | None:
    path = root / "wp-includes" / "version.php"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _VERSION_PHP_RE.search(text)
    return normalize_version(m.group(2)) if m else None


def find_content_dir(root: Path) -> Path | None:
    candidate = root / "wp-content"
    return candidate if candidate.is_dir() else None


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


_PLUGIN_HEADERS = ("Plugin Name", "Version", "Text Domain")
_THEME_HEADERS = ("Theme Name", "Version", "Template", "Text Domain")


def _plugin_from_dir(directory: Path, root: Path) -> Component | None:
    try:
        entries = sorted(p for p in directory.iterdir() if p.suffix.lower() == ".php" and p.is_file())
    except OSError:
        return None
    # WordPress picks the first file with a Plugin Name header; prefer <slug>.php.
    preferred = directory / f"{directory.name}.php"
    if preferred in entries:
        entries.remove(preferred)
        entries.insert(0, preferred)
    for php in entries:
        headers = read_file_headers(php, _PLUGIN_HEADERS)
        if "Plugin Name" in headers:
            raw = headers.get("Version")
            version = normalize_version(raw)
            notes = () if version else ("no Version header",)
            return Component(
                type="plugin",
                slug=directory.name.lower(),
                version=version,
                name=headers["Plugin Name"],
                location=_rel(php, root),
                notes=notes,
            )
    return None


def scan_plugins(plugins_dir: Path, root: Path, *, mu: bool = False) -> list[Component]:
    found: list[Component] = []
    if not plugins_dir.is_dir():
        return found
    for entry in sorted(plugins_dir.iterdir(), key=lambda p: p.name.lower()):
        if entry.name.startswith("."):
            continue
        if entry.is_dir() and not mu:
            comp = _plugin_from_dir(entry, root)
            if comp:
                found.append(comp)
        elif entry.is_file() and entry.suffix.lower() == ".php":
            headers = read_file_headers(entry, _PLUGIN_HEADERS)
            if "Plugin Name" not in headers:
                continue
            slug = SINGLE_FILE_SLUGS.get(entry.name.lower(), entry.stem.lower())
            version = normalize_version(headers.get("Version"))
            notes: tuple[str, ...] = ("must-use plugin",) if mu else ()
            if not version:
                notes = (*notes, "no Version header")
            found.append(
                Component(
                    type="plugin",
                    slug=slug,
                    version=version,
                    name=headers["Plugin Name"],
                    location=_rel(entry, root),
                    status="must-use" if mu else "",
                    notes=notes,
                )
            )
    return found


def scan_themes(themes_dir: Path, root: Path) -> list[Component]:
    found: list[Component] = []
    if not themes_dir.is_dir():
        return found
    for entry in sorted(themes_dir.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        style = entry / "style.css"
        headers = read_file_headers(style, _THEME_HEADERS)
        if "Theme Name" not in headers:
            continue
        version = normalize_version(headers.get("Version"))
        notes: list[str] = []
        if headers.get("Template"):
            notes.append(f"child theme of {headers['Template']}")
        if not version:
            notes.append("no Version header")
        found.append(
            Component(
                type="theme",
                slug=entry.name.lower(),
                version=version,
                name=headers["Theme Name"],
                location=_rel(style, root),
                notes=tuple(notes),
            )
        )
    return found


def scan_local(
    root: str | os.PathLike[str],
    *,
    content_dir: str | os.PathLike[str] | None = None,
    include_mu: bool = True,
    include_core: bool = True,
    include_plugins: bool = True,
    include_themes: bool = True,
) -> Inventory:
    """Build an inventory from a WordPress directory."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise WordPressNotFound(f"{root} is not a directory")
    inv = Inventory(target=str(base))
    core_version = read_core_version(base)
    content = Path(content_dir).expanduser().resolve() if content_dir else find_content_dir(base)
    if core_version is None and content is None:
        raise WordPressNotFound(f"{root} does not contain wp-includes/version.php or wp-content")
    if include_core:
        if core_version:
            inv.add(Component("core", "wordpress", core_version, "WordPress", "wp-includes/version.php"))
        else:
            inv.warnings.append("wp-includes/version.php not found or unreadable: core not checked")
    if content is None:
        inv.warnings.append("wp-content not found: plugins and themes not checked")
        return inv
    if include_plugins:
        for comp in scan_plugins(content / "plugins", base):
            inv.add(comp)
        if include_mu:
            for comp in scan_plugins(content / "mu-plugins", base, mu=True):
                inv.add(comp)
    if include_themes:
        for comp in scan_themes(content / "themes", base):
            inv.add(comp)
    for comp in inv.components:
        if comp.version is None:
            inv.warnings.append(f"{comp.type} {comp.slug}: version unknown, not checked")
    return inv
