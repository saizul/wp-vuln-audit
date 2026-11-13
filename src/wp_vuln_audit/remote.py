"""Best-effort version detection for a remote site, over plain HTTP(S).

This is opt-in (the CLI requires ``--allow-remote``) and polite: every request goes
through a :class:`~wp_vuln_audit.http.RateLimiter`, requests stay on the site's own host,
response bodies are capped and nothing but ``GET`` is sent.

What is requested:

1. The home page. It yields the core version from ``<meta name="generator">`` (when the
   site has not removed it), the ``?ver=`` of core assets as a fallback, and the plugin and
   theme slugs referenced under ``/wp-content/plugins/<slug>/`` and
   ``/wp-content/themes/<slug>/``.
2. ``/feed/`` for its ``<generator>`` element when the home page gave no core version.
3. ``/wp-content/plugins/<slug>/readme.txt`` for each plugin: ``Stable tag:``, or the
   newest ``= x.y =`` heading of the changelog when the stable tag is ``trunk`` or missing.
4. ``/wp-content/themes/<slug>/style.css`` for each theme: the ``Version:`` header.

Versions found this way are hints. A readme can be out of date, a site can hide or fake
its generator tag, and caching layers may serve old files. Findings from a remote scan are
marked ``source: remote`` so reports can say so.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .http import USER_AGENT, RateLimiter, Transport, TransportError, UrllibTransport, decode_body
from .inventory import Component, Inventory
from .versions import compare_versions, normalize_version, sort_versions

__all__ = [
    "RemoteOptions",
    "RemoteScanner",
    "extract_asset_slugs",
    "parse_generator",
    "parse_readme_version",
    "parse_style_version",
]

_SLUG = r"[a-z0-9][a-z0-9._-]*"
_PLUGIN_RE = re.compile(r"/wp-content/plugins/(" + _SLUG + r")/", re.IGNORECASE)
_THEME_RE = re.compile(r"/wp-content/themes/(" + _SLUG + r")/", re.IGNORECASE)
_META_GEN_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']generator["'][^>]*content\s*=\s*["']WordPress\s+([0-9][^"'\s]*)["']"""
    r"""|<meta[^>]+content\s*=\s*["']WordPress\s+([0-9][^"'\s]*)["'][^>]*name\s*=\s*["']generator["']""",
    re.IGNORECASE,
)
_FEED_GEN_RE = re.compile(r"<generator>\s*https?://wordpress\.org/\?v=([0-9][^<\s]*)\s*</generator>", re.IGNORECASE)
_CORE_ASSET_RE = re.compile(r"/wp-includes/[^\"'\s?]+\.(?:css|js)\?ver=([0-9][0-9.]*)", re.IGNORECASE)
_STABLE_RE = re.compile(r"^\s*stable\s+tag\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CHANGELOG_SECTION_RE = re.compile(r"^==\s*changelog\s*==\s*$(.*?)(?=^==[^=]|\Z)", re.IGNORECASE | re.MULTILINE | re.S)
_CHANGELOG_HEAD_RE = re.compile(r"^\s*=+\s*v?([0-9][0-9A-Za-z.\-]*)", re.MULTILINE)
_STYLE_VERSION_RE = re.compile(r"^[ \t/*#@]*Version:(.*)$", re.IGNORECASE | re.MULTILINE)

# Theme and plugin slugs that are part of every page and not separate software.
_IGNORED_SLUGS = {"index.php", "cache", "uploads"}


def parse_generator(html: str) -> str | None:
    m = _META_GEN_RE.search(html)
    if m:
        return normalize_version(m.group(1) or m.group(2))
    m = _FEED_GEN_RE.search(html)
    if m:
        return normalize_version(m.group(1))
    return None


def core_from_assets(html: str) -> str | None:
    """Most common ``?ver=`` on ``/wp-includes/`` assets (WordPress versions them with $wp_version)."""
    counts: dict[str, int] = {}
    for m in _CORE_ASSET_RE.finditer(html):
        v = m.group(1).rstrip(".")
        if v.count(".") >= 1:
            counts[v] = counts.get(v, 0) + 1
    if not counts:
        return None
    best = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
    return normalize_version(best[0])


def extract_asset_slugs(html: str) -> tuple[list[str], list[str]]:
    """Plugin and theme slugs referenced by asset URLs in ``html``."""
    plugins = sorted({m.group(1).lower() for m in _PLUGIN_RE.finditer(html)} - _IGNORED_SLUGS)
    themes = sorted({m.group(1).lower() for m in _THEME_RE.finditer(html)} - _IGNORED_SLUGS)
    return plugins, themes


def parse_readme_version(text: str) -> str | None:
    """Version from a WordPress.org ``readme.txt``."""
    m = _STABLE_RE.search(text)
    if m:
        tag = normalize_version(m.group(1))
        if tag and tag.lower() != "trunk" and any(ch.isdigit() for ch in tag):
            return tag
    section = _CHANGELOG_SECTION_RE.search(text)
    if section:
        versions = [normalize_version(v) for v in _CHANGELOG_HEAD_RE.findall(section.group(1))]
        clean = [v for v in versions if v]
        if clean:
            return sort_versions(clean)[-1]
    return None


def parse_style_version(text: str) -> str | None:
    head = text[:8192]
    m = _STYLE_VERSION_RE.search(head)
    if not m:
        return None
    return normalize_version(re.sub(r"\s*\*/.*", "", m.group(1)).strip())


@dataclass
class RemoteOptions:
    interval: float = 1.0
    max_requests: int = 40
    timeout: float = 15.0
    max_bytes: int = 2 * 1024 * 1024
    discover: bool = True
    plugins: list[str] = field(default_factory=list)
    themes: list[str] = field(default_factory=list)
    user_agent: str = USER_AGENT


class RemoteScanner:
    def __init__(
        self,
        base_url: str,
        options: RemoteOptions | None = None,
        *,
        transport: Transport | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        parts = urlsplit(base_url if "://" in base_url else "https://" + base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"not an http(s) URL: {base_url}")
        if "@" in parts.netloc:
            raise ValueError("URLs with credentials are not supported")
        path = parts.path if parts.path.endswith("/") else parts.path + "/"
        self.base = f"{parts.scheme}://{parts.netloc}{path}"
        self.host = parts.hostname.lower()
        self.options = options or RemoteOptions()
        self.transport = transport or UrllibTransport()
        self.limiter = limiter or RateLimiter(self.options.interval, self.options.max_requests)
        self.warnings: list[str] = []
        self.requests: list[str] = []

    def _get(self, path: str) -> str | None:
        url = urljoin(self.base, path)
        if (urlsplit(url).hostname or "").lower() != self.host:
            self.warnings.append(f"skipped off-site URL {url}")
            return None
        if not self.limiter.acquire():
            self.warnings.append(f"request budget of {self.limiter.max_requests} spent; skipped {url}")
            return None
        self.requests.append(url)
        headers = {"User-Agent": self.options.user_agent, "Accept-Encoding": "gzip"}
        try:
            resp = self.transport(url, headers, self.options.timeout, self.options.max_bytes)
        except TransportError as exc:
            self.warnings.append(str(exc))
            return None
        if resp.status != 200:
            return None
        try:
            body = decode_body(resp.body, resp.header("content-encoding"))
        except TransportError as exc:
            self.warnings.append(str(exc))
            return None
        return body[: self.options.max_bytes].decode("utf-8", errors="replace")

    def scan(self) -> Inventory:
        inv = Inventory(target=self.base)
        home = self._get("") or ""
        if not home:
            self.warnings.append(f"could not load {self.base}")
        core = parse_generator(home) or None
        core_source = "meta generator"
        if core is None:
            feed = self._get("feed/")
            core = parse_generator(feed or "")
            core_source = "feed generator"
        if core is None:
            core = core_from_assets(home)
            core_source = "core asset ?ver="
        if core:
            inv.add(Component("core", "wordpress", core, "WordPress", self.base, source="remote", notes=(core_source,)))
        else:
            self.warnings.append("WordPress core version not detected")

        plugins, themes = extract_asset_slugs(home) if self.options.discover else ([], [])
        plugins = _merge(plugins, self.options.plugins)
        themes = _merge(themes, self.options.themes)

        for slug in plugins:
            path = f"wp-content/plugins/{slug}/readme.txt"
            text = self._get(path)
            version = parse_readme_version(text) if text else None
            notes = ("readme.txt",) if version else ("version not detected",)
            inv.add(Component("plugin", slug, version, slug, urljoin(self.base, path), source="remote", notes=notes))
        for slug in themes:
            path = f"wp-content/themes/{slug}/style.css"
            text = self._get(path)
            version = parse_style_version(text) if text else None
            notes = ("style.css",) if version else ("version not detected",)
            inv.add(Component("theme", slug, version, slug, urljoin(self.base, path), source="remote", notes=notes))
        inv.warnings.extend(self.warnings)
        return inv


def _merge(found: Iterable[str], extra: Iterable[str]) -> list[str]:
    out: list[str] = []
    for slug in [*found, *extra]:
        s = slug.strip().lower()
        if s and re.fullmatch(_SLUG, s) and s not in out:
            out.append(s)
    return out


def newest(versions: Iterable[str]) -> str | None:
    best: str | None = None
    for v in versions:
        if best is None or compare_versions(v, best) > 0:
            best = v
    return best
