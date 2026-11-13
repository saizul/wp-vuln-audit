from __future__ import annotations

import pytest

from tests.conftest import FakeTransport, gzipped
from wp_vuln_audit.http import RateLimiter
from wp_vuln_audit.remote import (
    RemoteOptions,
    RemoteScanner,
    core_from_assets,
    extract_asset_slugs,
    newest,
    parse_generator,
    parse_readme_version,
    parse_style_version,
)

BASE = "https://shop.example.com/"

HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel='stylesheet' href='https://shop.example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2' />
<link rel='stylesheet' href='https://shop.example.com/wp-content/plugins/example-forms/assets/forms.css?ver=2.0.3' />
<script src='https://shop.example.com/wp-content/plugins/Cache-Helper/js/x.js?ver=1.3.0'></script>
<link rel='stylesheet' href='https://shop.example.com/wp-content/themes/demo-theme/style.css?ver=1.2' />
<img src="https://cdn.other.example/wp-content/plugins/cdn-only/logo.png">
</head><body></body></html>"""

README = """=== Example Forms ===
Contributors: someone
Requires at least: 6.0
Tested up to: 6.6
Stable tag: 2.0.3
License: GPLv2 or later

== Changelog ==
= 2.0.3 =
* Fix
"""

STYLE = "/*\nTheme Name: Demo Theme\nVersion: 1.2\n*/\n"


class NoSleepLimiter(RateLimiter):
    def __init__(self, max_requests: int = 50) -> None:
        self.slept: list[float] = []
        t = [0.0]
        super().__init__(1.0, max_requests, clock=lambda: t[0], sleep=self.slept.append)


def site(transport: FakeTransport) -> FakeTransport:
    transport.add(BASE, body=HOME)
    transport.add(BASE + "wp-content/plugins/example-forms/readme.txt", body=README)
    transport.add(
        BASE + "wp-content/plugins/cache-helper/readme.txt",
        body="=== C ===\nStable tag: trunk\n\n== Changelog ==\n= 1.3.0 =\n* x\n= 1.2.9 =\n",
    )
    transport.add(BASE + "wp-content/themes/demo-theme/style.css", body=STYLE)
    return transport


def test_full_remote_scan(transport: FakeTransport) -> None:
    site(transport)
    limiter = NoSleepLimiter()
    inv = RemoteScanner(BASE, transport=transport, limiter=limiter).scan()
    versions = {(c.type, c.slug): c.version for c in inv.components}
    assert versions == {
        ("core", "wordpress"): "6.4.2",
        ("plugin", "example-forms"): "2.0.3",
        ("plugin", "cache-helper"): "1.3.0",
        ("plugin", "cdn-only"): None,  # 404 on the site's own host
        ("theme", "demo-theme"): "1.2",
    }
    assert all(c.source == "remote" for c in inv.components)
    # Only the site's own host is ever requested.
    assert all(u.startswith(BASE) for u in transport.urls)
    assert transport.requests[0][1]["User-Agent"].startswith("wp-vuln-audit/")
    assert limiter.count == len(transport.urls) == 5


def test_explicit_slugs_without_discovery(transport: FakeTransport) -> None:
    site(transport)
    opts = RemoteOptions(discover=False, plugins=["example-forms", "bad slug!"], themes=["demo-theme"])
    inv = RemoteScanner("shop.example.com", opts, transport=transport, limiter=NoSleepLimiter()).scan()
    assert {c.slug for c in inv.components} == {"wordpress", "example-forms", "demo-theme"}


def test_budget_is_enforced(transport: FakeTransport) -> None:
    site(transport)
    inv = RemoteScanner(BASE, transport=transport, limiter=NoSleepLimiter(max_requests=2)).scan()
    assert len(transport.urls) == 2
    assert any("budget" in w for w in inv.warnings)


def test_core_from_feed_when_meta_removed(transport: FakeTransport) -> None:
    transport.add(BASE, body="<html><head></head></html>")
    transport.add(
        BASE + "feed/", body="<rss><channel><generator>https://wordpress.org/?v=6.5.3</generator></channel></rss>"
    )
    inv = RemoteScanner(BASE, transport=transport, limiter=NoSleepLimiter()).scan()
    assert inv.core is not None and inv.core.version == "6.5.3"
    assert inv.core.notes == ("feed generator",)


def test_core_from_assets_fallback(transport: FakeTransport) -> None:
    html = (
        "<link href='/wp-includes/css/dashicons.min.css?ver=6.6.1'>"
        "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>"
        "<script src='/wp-includes/js/wp-embed.min.js?ver=6.6.1'></script>"
    )
    transport.add(BASE, body=html)
    inv = RemoteScanner(BASE, transport=transport, limiter=NoSleepLimiter()).scan()
    assert inv.core is not None and inv.core.version == "6.6.1"


def test_unreachable_site(transport: FakeTransport) -> None:
    transport.errors[BASE] = "connection refused"
    inv = RemoteScanner(BASE, transport=transport, limiter=NoSleepLimiter()).scan()
    assert inv.core is None
    assert any("connection refused" in w for w in inv.warnings)
    assert any("not detected" in w for w in inv.warnings)


def test_gzip_bodies(transport: FakeTransport) -> None:
    transport.add(BASE, body=gzipped(HOME.encode()), headers={"Content-Encoding": "gzip"})
    inv = RemoteScanner(BASE, RemoteOptions(discover=False), transport=transport, limiter=NoSleepLimiter()).scan()
    assert inv.core is not None and inv.core.version == "6.4.2"


def test_subdirectory_install(transport: FakeTransport) -> None:
    base = "https://example.com/blog/"
    transport.add(base, body='<meta name="generator" content="WordPress 6.0.1">')
    inv = RemoteScanner("https://example.com/blog", transport=transport, limiter=NoSleepLimiter()).scan()
    assert inv.core is not None and inv.core.version == "6.0.1"
    assert transport.urls[0] == base


@pytest.mark.parametrize("url", ["ftp://example.com", "https://", "mailto:x@example.com"])
def test_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        RemoteScanner(url)


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ('<meta name="generator" content="WordPress 6.4.2" />', "6.4.2"),
        ("<META NAME='generator' CONTENT='WordPress 6.7-RC1'>", "6.7-RC1"),
        ('<meta content="WordPress 5.9" name="generator">', "5.9"),
        ('<meta name="generator" content="Site Kit by Google 1.0">', None),
        ("<generator>https://wordpress.org/?v=6.3</generator>", "6.3"),
        ("", None),
    ],
)
def test_parse_generator(html: str, expected: str | None) -> None:
    assert parse_generator(html) == expected


def test_extract_asset_slugs() -> None:
    plugins, themes = extract_asset_slugs(HOME)
    assert plugins == ["cache-helper", "cdn-only", "example-forms"]
    assert themes == ["demo-theme"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (README, "2.0.3"),
        ("Stable tag: v1.4\n", "1.4"),
        ("Stable tag: trunk\n== Changelog ==\n= 1.0 =\n* a\n= 1.10 =\n* b\n== Other ==\n= 9.9 =\n", "1.10"),
        ("== Changelog ==\n= v2.1.0 - 2026-01-01 =\n", "2.1.0"),
        ("no headers at all", None),
    ],
)
def test_parse_readme_version(text: str, expected: str | None) -> None:
    assert parse_readme_version(text) == expected


def test_parse_style_version() -> None:
    assert parse_style_version(STYLE) == "1.2"
    assert parse_style_version("/* Theme Name: X\n * Version: 2.0 */") == "2.0"
    assert parse_style_version("body{}") is None


def test_core_from_assets_needs_dotted_version() -> None:
    assert core_from_assets("<script src='/wp-includes/js/a.js?ver=20240101'></script>") is None


def test_newest() -> None:
    assert newest(["1.0", "1.10", "1.9"]) == "1.10"
    assert newest([]) is None


def test_rate_limiter_sleeps_between_requests() -> None:
    now = [100.0]
    slept: list[float] = []

    def sleep(s: float) -> None:
        slept.append(s)
        now[0] += s

    rl = RateLimiter(2.0, 3, clock=lambda: now[0], sleep=sleep)
    assert rl.acquire()
    now[0] += 0.5
    assert rl.acquire()
    assert slept == [1.5]
    now[0] += 5
    assert rl.acquire()
    assert slept == [1.5]
    assert not rl.acquire()
    assert rl.remaining == 0


@pytest.mark.parametrize(("interval", "count"), [(-1, 1), (1, 0)])
def test_rate_limiter_validation(interval: float, count: int) -> None:
    with pytest.raises(ValueError):
        RateLimiter(interval, count)
