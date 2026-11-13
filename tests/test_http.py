from __future__ import annotations

import gzip
import socketserver
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wp_vuln_audit.http import TransportError, UrllibTransport, decode_body


def test_decode_body_variants() -> None:
    assert decode_body(b"plain", None) == b"plain"
    assert decode_body(gzip.compress(b"zipped"), "gzip") == b"zipped"
    assert decode_body(gzip.compress(b"sniffed"), None) == b"sniffed"
    assert decode_body(zlib.compress(b"deflated"), "deflate") == b"deflated"
    raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    assert decode_body(raw.compress(b"raw") + raw.flush(), "deflate") == b"raw"
    with pytest.raises(TransportError):
        decode_body(b"\x1f\x8bnot gzip", "gzip")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            body = b"hello"
            self.send_response(200)
            self.send_header("ETag", '"e1"')
        elif self.path == "/big":
            body = b"x" * 5000
            self.send_response(200)
        elif self.path == "/notmod":
            self.send_response(304)
            self.end_headers()
            return
        else:
            body = b"missing"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class _QuickServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer.server_bind() calls socket.getfqdn(), which can stall on DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


@pytest.fixture
def server():
    srv = _QuickServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_urllib_transport_against_local_server(server: str) -> None:
    t = UrllibTransport()
    ok = t(f"{server}/ok", {"User-Agent": "test"}, 5, 1000)
    assert ok.status == 200 and ok.body == b"hello" and ok.header("etag") == '"e1"'
    assert t(f"{server}/missing", {}, 5, 1000).status == 404
    assert t(f"{server}/notmod", {}, 5, 1000).status == 304
    with pytest.raises(TransportError, match="larger"):
        t(f"{server}/big", {}, 5, 100)


def test_urllib_transport_errors() -> None:
    t = UrllibTransport()
    with pytest.raises(TransportError):
        t("file:///etc/passwd", {}, 1, 10)
    with pytest.raises(TransportError):
        t("http://127.0.0.1:9/", {}, 1, 10)
