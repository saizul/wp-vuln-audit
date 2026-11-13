"""Downloading the Wordfence Intelligence feed with an on-disk cache.

The feed is large and changes a few times a day, so it is stored on disk next to a small
metadata file (``<name>.meta.json``) holding the ``ETag`` and ``Last-Modified`` values of
the last download. A refresh sends them back as ``If-None-Match`` and
``If-Modified-Since``; a ``304 Not Modified`` answer keeps the cached copy and only
updates the time it was last checked. Within ``max_age`` seconds of the last check the
network is not used at all.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .feed import Feed
from .http import USER_AGENT, Transport, TransportError, UrllibTransport, decode_body

__all__ = [
    "DEFAULT_BASE_URL",
    "FEED_VARIANTS",
    "CacheMeta",
    "FeedError",
    "FeedSource",
    "FetchResult",
    "default_cache_dir",
]

DEFAULT_BASE_URL = "https://www.wordfence.com/api/intelligence/v3"
FEED_VARIANTS = ("production", "scanner")
DEFAULT_MAX_AGE = 6 * 3600
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024  # 1 GiB, the production feed is a few hundred MiB


class FeedError(Exception):
    """The feed could not be downloaded or read."""


def default_cache_dir() -> Path:
    base = os.environ.get("WP_VULN_AUDIT_CACHE") or ""
    if base:
        return Path(base)
    xdg = os.environ.get("XDG_CACHE_HOME") or ""
    root = Path(xdg) if xdg else Path.home() / ".cache"
    return root / "wp-vuln-audit"


@dataclass
class CacheMeta:
    url: str = ""
    etag: str | None = None
    last_modified: str | None = None
    fetched_at: float = 0.0
    checked_at: float = 0.0
    size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "fetched_at": self.fetched_at,
            "checked_at": self.checked_at,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheMeta:
        return cls(
            url=str(data.get("url") or ""),
            etag=data.get("etag") or None,
            last_modified=data.get("last_modified") or None,
            fetched_at=float(data.get("fetched_at") or 0),
            checked_at=float(data.get("checked_at") or 0),
            size=int(data.get("size") or 0),
        )


@dataclass
class FetchResult:
    feed: Feed
    status: str  # "downloaded", "not-modified", "cached", "stale-cache", "file"
    meta: CacheMeta | None = None
    message: str = ""


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class FeedSource:
    """Fetches one feed variant, using and updating the cache."""

    def __init__(
        self,
        variant: str = "production",
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        cache_dir: Path | str | None = None,
        transport: Transport | None = None,
        max_age: float = DEFAULT_MAX_AGE,
        timeout: float = 120.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if variant not in FEED_VARIANTS:
            raise ValueError(f"unknown feed variant {variant!r}, expected one of {', '.join(FEED_VARIANTS)}")
        self.variant = variant
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.cache_dir = Path(cache_dir) if cache_dir is not None else default_cache_dir()
        self.transport = transport or UrllibTransport()
        self.max_age = max_age
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.clock = clock

    @property
    def url(self) -> str:
        return f"{self.base_url}/vulnerabilities/{self.variant}"

    @property
    def data_path(self) -> Path:
        return self.cache_dir / f"feed-{self.variant}.json"

    @property
    def meta_path(self) -> Path:
        return self.cache_dir / f"feed-{self.variant}.meta.json"

    def read_meta(self) -> CacheMeta | None:
        try:
            data = json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        meta = CacheMeta.from_dict(data)
        if not self.data_path.exists():
            return None
        return meta

    def _write_meta(self, meta: CacheMeta) -> None:
        _atomic_write(self.meta_path, json.dumps(meta.to_dict(), indent=2).encode("utf-8"))

    def _load_cached(self) -> Feed:
        try:
            return Feed.from_file(str(self.data_path))
        except (OSError, ValueError) as exc:
            raise FeedError(f"cached feed {self.data_path} is unreadable: {exc}") from exc

    def headers(self, meta: CacheMeta | None) -> dict[str, str]:
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "gzip"}
        if self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        if meta is not None and meta.url == self.url:
            if meta.etag:
                hdrs["If-None-Match"] = meta.etag
            if meta.last_modified:
                hdrs["If-Modified-Since"] = meta.last_modified
        return hdrs

    def load(self, *, refresh: bool = False, offline: bool = False) -> FetchResult:
        """Return the feed, downloading it only when the cache is missing or stale.

        ``refresh`` forces a (conditional) request even when the cache is fresh.
        ``offline`` never uses the network and fails when there is no cache.
        """
        meta = self.read_meta()
        now = self.clock()
        if offline:
            if meta is None:
                raise FeedError(f"no cached {self.variant} feed in {self.cache_dir} (run `wp-vuln-audit feed update`)")
            return FetchResult(self._load_cached(), "cached", meta, "offline: using cached feed")
        if meta is not None and not refresh and now - meta.checked_at < self.max_age:
            return FetchResult(self._load_cached(), "cached", meta)
        return self._download(meta, now)

    def _download(self, meta: CacheMeta | None, now: float) -> FetchResult:
        if not self.api_key:
            if meta is not None:
                return FetchResult(
                    self._load_cached(), "stale-cache", meta, "no API key set: using the cached feed without refreshing"
                )
            raise FeedError(
                "the Wordfence Intelligence v3 feed needs a free API key: set WORDFENCE_API_KEY "
                "or pass --api-key (or use --feed-file with a downloaded copy)"
            )
        try:
            resp = self.transport(self.url, self.headers(meta), self.timeout, self.max_bytes)
        except TransportError as exc:
            if meta is not None:
                return FetchResult(
                    self._load_cached(), "stale-cache", meta, f"feed refresh failed ({exc}); using cache"
                )
            raise FeedError(f"could not download the feed: {exc}") from exc

        if resp.status == 304 and meta is not None:
            meta.checked_at = now
            self._write_meta(meta)
            return FetchResult(self._load_cached(), "not-modified", meta)
        if resp.status in (401, 403):
            raise FeedError(f"the feed rejected the API key (HTTP {resp.status}); check WORDFENCE_API_KEY")
        if resp.status != 200:
            if meta is not None:
                return FetchResult(
                    self._load_cached(), "stale-cache", meta, f"feed returned HTTP {resp.status}; using cache"
                )
            raise FeedError(f"the feed returned HTTP {resp.status}")

        body = decode_body(resp.body, resp.header("content-encoding"))
        feed = Feed.from_bytes(body)  # validate before replacing the cache
        if len(feed) == 0 and feed.skipped == 0:
            raise FeedError("the feed is empty")
        _atomic_write(self.data_path, body)
        new_meta = CacheMeta(
            url=self.url,
            etag=resp.header("etag"),
            last_modified=resp.header("last-modified"),
            fetched_at=now,
            checked_at=now,
            size=len(body),
        )
        self._write_meta(new_meta)
        return FetchResult(feed, "downloaded", new_meta)

    def clear(self) -> bool:
        removed = False
        for path in (self.data_path, self.meta_path):
            try:
                path.unlink()
                removed = True
            except FileNotFoundError:
                pass
        return removed
