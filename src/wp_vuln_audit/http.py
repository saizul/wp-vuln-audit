"""Small HTTP layer: an injectable transport, gzip handling, size limits and rate limiting."""

from __future__ import annotations

import gzip
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from ._version import __version__

__all__ = [
    "USER_AGENT",
    "RateLimiter",
    "Response",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "decode_body",
]

USER_AGENT = f"wp-vuln-audit/{__version__} (+https://github.com/saizul/wp-vuln-audit)"


class TransportError(Exception):
    """Network failure, timeout or a response larger than allowed."""


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    url: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


# A transport takes (url, headers, timeout, max_bytes) and returns a Response for every
# HTTP status (including 304 and 4xx/5xx); it raises TransportError for network problems.
Transport = Callable[[str, dict[str, str], float, int], Response]


def decode_body(body: bytes, content_encoding: str | None) -> bytes:
    enc = (content_encoding or "").strip().lower()
    if enc == "gzip" or (not enc and body[:2] == b"\x1f\x8b"):
        try:
            return gzip.decompress(body)
        except (OSError, EOFError) as exc:
            raise TransportError(f"invalid gzip body: {exc}") from exc
    if enc == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    return body


class UrllibTransport:
    """Default transport built on :mod:`urllib.request`."""

    def __call__(self, url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> Response:
        if not url.lower().startswith(("https://", "http://")):
            raise TransportError(f"unsupported URL scheme: {url}")
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes + 1) if exc.fp else b""
            return Response(exc.code, {k.lower(): v for k, v in exc.headers.items()}, body, url)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise TransportError(f"{url}: {reason}") from exc
        with resp:
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise TransportError(f"{url}: response larger than {max_bytes} bytes")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return Response(resp.status, hdrs, body, resp.geturl())


class RateLimiter:
    """Allows one request per ``interval`` seconds and at most ``max_requests`` in total."""

    def __init__(
        self,
        interval: float = 1.0,
        max_requests: int = 50,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if interval < 0:
            raise ValueError("interval must be >= 0")
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        self.interval = interval
        self.max_requests = max_requests
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None
        self.count = 0

    @property
    def remaining(self) -> int:
        return self.max_requests - self.count

    def acquire(self) -> bool:
        """Wait for the next slot. Returns ``False`` when the request budget is spent."""
        if self.count >= self.max_requests:
            return False
        if self._last is not None:
            wait = self.interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()
        self.count += 1
        return True
