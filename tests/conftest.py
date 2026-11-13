from __future__ import annotations

import gzip
from collections.abc import Callable
from pathlib import Path

import pytest

from wp_vuln_audit.feed import Feed
from wp_vuln_audit.http import Response, TransportError

FIXTURES = Path(__file__).parent / "fixtures"
PRODUCTION_FEED = FIXTURES / "feed-production.json"
SCANNER_FEED = FIXTURES / "feed-scanner.json"


def vid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


@pytest.fixture(scope="session")
def feed() -> Feed:
    return Feed.from_file(str(PRODUCTION_FEED))


@pytest.fixture(scope="session")
def scanner_feed() -> Feed:
    return Feed.from_file(str(SCANNER_FEED))


class FakeTransport:
    """Serves canned responses by URL and records every request."""

    def __init__(self, routes: dict[str, Response | Callable[[dict[str, str]], Response]] | None = None):
        self.routes = routes or {}
        self.errors: dict[str, str] = {}
        self.requests: list[tuple[str, dict[str, str]]] = []

    def add(self, url: str, status: int = 200, body: bytes | str = b"", headers: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.routes[url] = Response(status, {k.lower(): v for k, v in (headers or {}).items()}, raw, url)

    def __call__(self, url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> Response:
        self.requests.append((url, dict(headers)))
        if url in self.errors:
            raise TransportError(self.errors[url])
        route = self.routes.get(url)
        if route is None:
            return Response(404, {}, b"not found", url)
        if callable(route):
            return route(headers)
        return route

    @property
    def urls(self) -> list[str]:
        return [u for u, _ in self.requests]


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


def gzipped(data: bytes) -> bytes:
    return gzip.compress(data)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def plugin_header(name: str, version: str | None, extra: str = "") -> str:
    lines = ["<?php", "/**", f" * Plugin Name: {name}", " * Description: Fixture plugin."]
    if version is not None:
        lines.append(f" * Version: {version}")
    if extra:
        lines.append(extra)
    lines += [" */", "", "defined( 'ABSPATH' ) || exit;", ""]
    return "\n".join(lines)


def theme_header(name: str, version: str | None, template: str | None = None) -> str:
    lines = ["/*", f"Theme Name: {name}", "Author: Fixture"]
    if version is not None:
        lines.append(f"Version: {version}")
    if template:
        lines.append(f"Template: {template}")
    lines += ["*/", "body { margin: 0; }", ""]
    return "\n".join(lines)


def make_wp(
    root: Path,
    core: str | None = "6.4.2",
    plugins: dict[str, str | None] | None = None,
    themes: dict[str, str | None] | None = None,
) -> Path:
    """Create a fake WordPress tree."""
    if core is not None:
        write(
            root / "wp-includes" / "version.php",
            "<?php\n/**\n * WordPress Version\n */\n\n"
            f"$wp_version = '{core}';\n\n$wp_db_version = 57155;\n$tinymce_version = '49110-20201110';\n",
        )
    (root / "wp-content" / "plugins").mkdir(parents=True, exist_ok=True)
    (root / "wp-content" / "themes").mkdir(parents=True, exist_ok=True)
    for slug, version in (plugins or {}).items():
        write(root / "wp-content" / "plugins" / slug / f"{slug}.php", plugin_header(slug.title(), version))
    for slug, version in (themes or {}).items():
        write(root / "wp-content" / "themes" / slug / "style.css", theme_header(slug.title(), version))
    return root


@pytest.fixture
def wp_site(tmp_path: Path) -> Path:
    return make_wp(
        tmp_path / "site",
        core="6.4.2",
        plugins={"example-forms": "2.0.3", "cache-helper": "1.3.0", "safe-plugin": "1.0.0", "demo-slider": "4.2"},
        themes={"demo-theme": "1.2", "twentytwentyfour": "1.0"},
    )
