from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import PRODUCTION_FEED, FakeTransport, gzipped
from wp_vuln_audit.cache import DEFAULT_BASE_URL, FeedError, FeedSource, default_cache_dir
from wp_vuln_audit.http import Response

URL = f"{DEFAULT_BASE_URL}/vulnerabilities/production"
BODY = PRODUCTION_FEED.read_bytes()


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def source(tmp_path: Path, transport: FakeTransport, clock: Clock | None = None, **kw) -> FeedSource:
    return FeedSource(
        "production", api_key="test-key", cache_dir=tmp_path, transport=transport, clock=clock or Clock(), **kw
    )


def test_first_download_writes_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY, headers={"ETag": '"abc"', "Last-Modified": "Wed, 11 Nov 2026 10:00:00 GMT"})
    src = source(tmp_path, transport)
    result = src.load()
    assert result.status == "downloaded"
    assert len(result.feed) == 12
    url, headers = transport.requests[0]
    assert url == URL
    assert headers["Authorization"] == "Bearer test-key"
    assert headers["Accept-Encoding"] == "gzip"
    assert "If-None-Match" not in headers
    meta = json.loads(src.meta_path.read_text())
    assert meta["etag"] == '"abc"' and meta["last_modified"].startswith("Wed")
    assert src.data_path.read_bytes() == BODY


def test_fresh_cache_skips_network(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY, headers={"ETag": '"abc"'})
    clock = Clock()
    src = source(tmp_path, transport, clock, max_age=3600)
    src.load()
    clock.t += 60
    assert src.load().status == "cached"
    assert len(transport.requests) == 1


def test_conditional_request_and_304(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY, headers={"ETag": '"abc"', "Last-Modified": "Wed, 11 Nov 2026 10:00:00 GMT"})
    clock = Clock()
    src = source(tmp_path, transport, clock, max_age=3600)
    src.load()
    transport.add(URL, status=304)
    clock.t += 7200
    result = src.load()
    assert result.status == "not-modified"
    assert len(result.feed) == 12
    _, headers = transport.requests[-1]
    assert headers["If-None-Match"] == '"abc"'
    assert headers["If-Modified-Since"] == "Wed, 11 Nov 2026 10:00:00 GMT"
    assert src.read_meta().checked_at == clock.t
    # And the cache is fresh again.
    clock.t += 10
    assert src.load().status == "cached"


def test_refresh_forces_revalidation(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY, headers={"ETag": '"abc"'})
    src = source(tmp_path, transport)
    src.load()
    transport.add(URL, status=304)
    assert src.load(refresh=True).status == "not-modified"
    assert len(transport.requests) == 2


def test_gzip_response(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=gzipped(BODY), headers={"Content-Encoding": "gzip"})
    src = source(tmp_path, transport)
    assert len(src.load().feed) == 12
    assert src.data_path.read_bytes() == BODY  # stored decompressed


def test_offline(tmp_path: Path, transport: FakeTransport) -> None:
    src = source(tmp_path, transport)
    with pytest.raises(FeedError, match="no cached"):
        src.load(offline=True)
    transport.add(URL, body=BODY)
    src.load()
    assert src.load(offline=True).status == "cached"
    assert len(transport.requests) == 1


def test_missing_api_key(tmp_path: Path, transport: FakeTransport) -> None:
    src = FeedSource("production", cache_dir=tmp_path, transport=transport)
    with pytest.raises(FeedError, match="API key"):
        src.load()
    assert transport.requests == []


def test_missing_api_key_uses_stale_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY)
    clock = Clock()
    source(tmp_path, transport, clock).load()
    clock.t += 10**6
    src = FeedSource("production", cache_dir=tmp_path, transport=transport, clock=clock)
    result = src.load()
    assert result.status == "stale-cache" and "no API key" in result.message


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors(tmp_path: Path, transport: FakeTransport, status: int) -> None:
    transport.add(URL, status=status, body=b'{"message": "Unauthorized"}')
    with pytest.raises(FeedError, match="API key"):
        source(tmp_path, transport).load()


def test_server_error_without_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, status=503)
    with pytest.raises(FeedError, match="503"):
        source(tmp_path, transport).load()


def test_errors_fall_back_to_stale_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY)
    clock = Clock()
    src = source(tmp_path, transport, clock)
    src.load()
    clock.t += 10**6
    transport.add(URL, status=500)
    assert src.load().status == "stale-cache"
    transport.errors[URL] = "timed out"
    result = src.load()
    assert result.status == "stale-cache" and "timed out" in result.message


def test_network_error_without_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.errors[URL] = "dns failure"
    with pytest.raises(FeedError, match="dns failure"):
        source(tmp_path, transport).load()


def test_invalid_download_does_not_replace_cache(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY)
    src = source(tmp_path, transport)
    src.load()
    transport.add(URL, body=b"<html>maintenance</html>")
    with pytest.raises(ValueError):
        src.load(refresh=True)
    assert src.data_path.read_bytes() == BODY


def test_empty_feed_rejected(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=b"{}")
    with pytest.raises(FeedError, match="empty"):
        source(tmp_path, transport).load()


def test_304_without_cache_is_an_error(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, status=304)
    with pytest.raises(FeedError):
        source(tmp_path, transport).load()


def test_corrupt_meta_or_data(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY)
    src = source(tmp_path, transport)
    src.load()
    src.meta_path.write_text("{not json")
    assert src.read_meta() is None
    src.load()  # downloads again
    src.data_path.write_text("garbage")
    with pytest.raises(FeedError, match="unreadable"):
        src.load(offline=True)


def test_meta_for_another_url_sends_no_validators(tmp_path: Path, transport: FakeTransport) -> None:
    other = "https://mirror.example.com/v3"
    transport.add(f"{other}/vulnerabilities/production", body=BODY, headers={"ETag": '"m"'})
    FeedSource("production", api_key="k", base_url=other, cache_dir=tmp_path, transport=transport).load()
    transport.add(URL, body=BODY)
    source(tmp_path, transport).load(refresh=True)
    assert "If-None-Match" not in transport.requests[-1][1]


def test_clear(tmp_path: Path, transport: FakeTransport) -> None:
    transport.add(URL, body=BODY)
    src = source(tmp_path, transport)
    assert not src.clear()
    src.load()
    assert src.clear()
    assert not src.data_path.exists() and not src.meta_path.exists()


def test_variants_and_urls(tmp_path: Path) -> None:
    assert FeedSource("scanner", cache_dir=tmp_path).url.endswith("/v3/vulnerabilities/scanner")
    with pytest.raises(ValueError):
        FeedSource("bogus")


def test_callable_route_sees_headers(tmp_path: Path) -> None:
    seen = {}

    def route(headers):
        seen.update(headers)
        return Response(200, {}, BODY, URL)

    t = FakeTransport({URL: route})
    source(tmp_path, t).load()
    assert seen["Accept"] == "application/json"


def test_default_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WP_VULN_AUDIT_CACHE", str(tmp_path / "a"))
    assert default_cache_dir() == tmp_path / "a"
    monkeypatch.delenv("WP_VULN_AUDIT_CACHE")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_dir() == tmp_path / "xdg" / "wp-vuln-audit"
    monkeypatch.delenv("XDG_CACHE_HOME")
    assert default_cache_dir().name == "wp-vuln-audit"
