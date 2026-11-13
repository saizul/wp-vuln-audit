from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from tests.conftest import PRODUCTION_FEED, SCANNER_FEED, FakeTransport, make_wp, vid
from wp_vuln_audit import __version__
from wp_vuln_audit.cache import DEFAULT_BASE_URL
from wp_vuln_audit.cli import main
from wp_vuln_audit.http import RateLimiter

FEED = str(PRODUCTION_FEED)


def run(argv, *, stdin: str = "", transport=None, limiter=None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), stdout=out, stderr=err, transport=transport, limiter=limiter)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    monkeypatch.setenv("WP_VULN_AUDIT_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("NO_COLOR", "1")


def test_version(capsys) -> None:
    code, _, _ = run(["--version"])
    assert code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command() -> None:
    code, out, _ = run([])
    assert code == 2 and "usage" in out.lower()


def test_scan_local_site_text(wp_site: Path) -> None:
    code, out, err = run(["scan", str(wp_site), "--feed-file", FEED])
    assert code == 1, err
    assert "WordPress 6.4.2" in out
    assert "Example Forms <= 2.4.1 - Unauthenticated SQL Injection" in out
    assert "plugin demo-slider 4.2" in out


def test_scan_json_and_output_file(wp_site: Path, tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    code, out, err = run(["scan", str(wp_site), "--feed-file", FEED, "-f", "json", "-o", str(target)])
    assert code == 1
    assert out == ""
    assert "wrote json report" in err
    data = json.loads(target.read_text())
    assert {f["id"] for f in data["findings"]} == {vid(1), vid(3), vid(4), vid(5), vid(6), vid(7)}
    assert data["feed"]["status"] == "file"


@pytest.mark.parametrize(("fail_on", "code"), [("any", 1), ("critical", 1), ("never", 0)])
def test_fail_on(wp_site: Path, fail_on: str, code: int) -> None:
    assert run(["scan", str(wp_site), "--feed-file", FEED, "--fail-on", fail_on])[0] == code


def test_fail_on_threshold_not_reached(tmp_path: Path) -> None:
    root = make_wp(tmp_path / "s", core="6.4.3", plugins={"cache-helper": "1.3.0"})  # low only
    assert run(["scan", str(root), "--feed-file", FEED, "--fail-on", "medium"])[0] == 0
    assert run(["scan", str(root), "--feed-file", FEED, "--fail-on", "low"])[0] == 1


def test_clean_site_exits_zero(tmp_path: Path) -> None:
    root = make_wp(tmp_path / "s", core="6.6.2", plugins={"safe": "1.0"})
    code, out, _ = run(["scan", str(root), "--feed-file", FEED])
    assert code == 0 and "No known vulnerabilities found." in out


def test_min_severity(wp_site: Path) -> None:
    code, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--min-severity", "high", "-f", "json"])
    assert code == 1
    data = json.loads(out)
    assert {f["severity"] for f in data["findings"]} <= {"high", "critical"}
    assert data["summary"]["filtered"] > 0


def test_min_severity_warns_for_scanner_feed(wp_site: Path) -> None:
    _, _, err = run(["scan", str(wp_site), "--feed-file", str(SCANNER_FEED), "--min-cvss", "7"])
    assert "no CVSS scores" in err


def test_ignore_file_in_cwd(wp_site: Path, tmp_path: Path) -> None:
    (tmp_path / ".wpvulnignore").write_text(
        "plugin:example-forms\ncore\nplugin:demo-slider\nplugin:cache-helper\ntheme:demo-theme\n"
    )
    code, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--show-ignored"])
    assert code == 0
    assert "Ignored:" in out
    code, _, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--no-ignore-file"])
    assert code == 1


def test_ignore_file_in_site_root(wp_site: Path) -> None:
    (wp_site / ".wpvulnignore").write_text("plugin:example-forms\n")
    _, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "-f", "json"])
    assert all(f["component"]["slug"] != "example-forms" for f in json.loads(out)["findings"])


def test_explicit_ignore_file_errors(wp_site: Path, tmp_path: Path) -> None:
    code, _, err = run(["scan", str(wp_site), "--feed-file", FEED, "--ignore-file", str(tmp_path / "missing")])
    assert code == 2 and "cannot read ignore file" in err
    bad = tmp_path / "bad.ignore"
    bad.write_text("what is this\n")
    code, _, err = run(["scan", str(wp_site), "--feed-file", FEED, "--ignore-file", str(bad)])
    assert code == 2 and "bad.ignore:1" in err


def test_wp_cli_inputs(tmp_path: Path) -> None:
    plugins = tmp_path / "plugins.json"
    plugins.write_text(json.dumps([{"name": "example-forms", "status": "active", "version": "2.4.1"}]))
    themes = tmp_path / "themes.json"
    themes.write_text(json.dumps([{"name": "demo-theme", "status": "active", "version": "1.3"}]))
    code, out, _ = run(
        [
            "scan",
            "--plugins-json",
            str(plugins),
            "--themes-json",
            str(themes),
            "--core-version",
            "6.5.1",
            "--feed-file",
            FEED,
            "-f",
            "json",
        ]
    )
    assert code == 1
    data = json.loads(out)
    assert {f["id"] for f in data["findings"]} == {vid(2), vid(3), vid(7)}


def test_wp_cli_combined_from_stdin() -> None:
    doc = {"core": "6.4.3", "plugins": [{"name": "cache-helper", "version": "1.3.0"}]}
    code, out, _ = run(["scan", "--wp-cli", "-", "--feed-file", FEED, "-f", "json"], stdin=json.dumps(doc))
    assert code == 1
    assert [f["id"] for f in json.loads(out)["findings"]] == [vid(6)]


def test_core_version_from_file(tmp_path: Path) -> None:
    f = tmp_path / "core.txt"
    f.write_text("WordPress version: 6.4.2\n")
    code, out, _ = run(["scan", "--core-version", str(f), "--feed-file", FEED, "-f", "json"])
    assert [x["id"] for x in json.loads(out)["findings"]] == [vid(1)]
    code, _, err = run(["scan", "--core-version", "<bad>", "--feed-file", FEED])
    assert code == 2 and "--core-version" in err


def test_nothing_to_scan() -> None:
    code, _, err = run(["scan", "--feed-file", FEED])
    assert code == 2 and "nothing to scan" in err


def test_not_wordpress(tmp_path: Path) -> None:
    code, _, err = run(["scan", str(tmp_path), "--feed-file", FEED])
    assert code == 2 and "does not contain" in err


def test_bad_wp_cli_json(tmp_path: Path) -> None:
    p = tmp_path / "p.json"
    p.write_text("Error: not a WordPress install")
    assert run(["scan", "--plugins-json", str(p), "--feed-file", FEED])[0] == 2
    assert run(["scan", "--plugins-json", str(tmp_path / "missing.json"), "--feed-file", FEED])[0] == 2


def test_remote_requires_opt_in() -> None:
    code, _, err = run(["scan", "--url", "https://example.com", "--feed-file", FEED])
    assert code == 2 and "--allow-remote" in err
    code, _, err = run(["scan", "--remote-plugin", "x", "--feed-file", FEED])
    assert code == 2 and "need --url" in err


def test_remote_scan(transport: FakeTransport) -> None:
    base = "https://blog.example.com/"
    transport.add(base, body='<meta name="generator" content="WordPress 6.5.2">')
    transport.add(base + "wp-content/plugins/example-forms/readme.txt", body="Stable tag: 2.4.0\n")
    limiter = RateLimiter(0, 10)
    code, out, _ = run(
        [
            "scan",
            "--url",
            base,
            "--allow-remote",
            "--remote-plugin",
            "example-forms",
            "--feed-file",
            FEED,
            "-f",
            "json",
        ],
        transport=transport,
        limiter=limiter,
    )
    assert code == 1
    data = json.loads(out)
    assert {f["id"] for f in data["findings"]} == {vid(2), vid(3)}
    assert all(c["source"] == "remote" for c in data["components"])


def test_remote_bad_limits() -> None:
    code, _, _ = run(
        ["scan", "--url", "https://x.example", "--allow-remote", "--max-requests", "0", "--feed-file", FEED]
    )
    assert code == 2


def test_check_command() -> None:
    code, out, _ = run(["check", "plugin", "example-forms", "2.0.3", "--feed-file", FEED, "-f", "json"])
    assert code == 1
    assert {f["id"] for f in json.loads(out)["findings"]} == {vid(3), vid(4)}
    code, out, _ = run(["check", "core", "6.4.3", "--feed-file", FEED])
    assert code == 0
    code, out, _ = run(["check", "core", "wordpress", "6.4.2", "--feed-file", FEED])
    assert code == 1
    assert run(["check", "plugin", "example-forms", "--feed-file", FEED])[0] == 2
    assert run(["check", "plugin", "example-forms", "<x>", "--feed-file", FEED])[0] == 2


@pytest.mark.parametrize("fmt", ["markdown", "sarif", "md"])
def test_other_formats(wp_site: Path, fmt: str) -> None:
    code, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "-f", fmt])
    assert code == 1
    if fmt == "sarif":
        assert json.loads(out)["version"] == "2.1.0"
    else:
        assert out.startswith("## WordPress vulnerability audit")


def test_color_always(wp_site: Path) -> None:
    _, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--color", "always"])
    assert "\033[" in out


def test_inventory_command(wp_site: Path) -> None:
    code, out, _ = run(["inventory", str(wp_site)])
    assert code == 0
    assert "example-forms" in out and "6.4.2" in out
    code, out, _ = run(["inventory", str(wp_site), "-f", "json"])
    assert len(json.loads(out)["components"]) == 7


def test_feed_file_errors(wp_site: Path, tmp_path: Path) -> None:
    code, _, err = run(["scan", str(wp_site), "--feed-file", str(tmp_path / "nope.json")])
    assert code == 3 and "feed error" in err
    bad = tmp_path / "bad.json"
    bad.write_text("[not json")
    assert run(["scan", str(wp_site), "--feed-file", str(bad)])[0] == 3


def test_api_feed_needs_key(wp_site: Path) -> None:
    code, _, err = run(["scan", str(wp_site)])
    assert code == 3 and "WORDFENCE_API_KEY" in err


def test_feed_update_info_clear(monkeypatch: pytest.MonkeyPatch, transport: FakeTransport) -> None:
    monkeypatch.setenv("WORDFENCE_API_KEY", "test-key")
    url = f"{DEFAULT_BASE_URL}/vulnerabilities/production"
    transport.add(url, body=PRODUCTION_FEED.read_bytes(), headers={"ETag": '"v1"'})
    code, out, _ = run(["feed", "info"], transport=transport)
    assert code == 3 and "no cached" in out
    code, out, _ = run(["feed", "update"], transport=transport)
    assert code == 0 and "downloaded, 12 records" in out
    assert transport.requests[0][1]["Authorization"] == "Bearer test-key"
    transport.add(url, status=304)
    code, out, _ = run(["feed", "update"], transport=transport)
    assert code == 0 and "not-modified" in out
    code, out, _ = run(["feed", "info"], transport=transport)
    info = json.loads(out)
    assert info["records"] == 12 and info["etag"] == '"v1"' and info["with_cvss"] == 10
    # A scan now uses the cache without the network.
    n = len(transport.requests)
    code, _, _ = run(["check", "core", "6.4.2"], transport=transport)
    assert code == 1 and len(transport.requests) == n
    code, out, _ = run(["feed", "clear"], transport=transport)
    assert "removed" in out


def test_feed_update_failure_uses_stale_cache(monkeypatch: pytest.MonkeyPatch, transport: FakeTransport) -> None:
    monkeypatch.setenv("WORDFENCE_API_KEY", "k")
    url = f"{DEFAULT_BASE_URL}/vulnerabilities/production"
    transport.add(url, body=PRODUCTION_FEED.read_bytes())
    run(["feed", "update"], transport=transport)
    transport.add(url, status=500)
    code, out, err = run(["feed", "update"], transport=transport)
    assert code == 3 and "stale-cache" in out and "HTTP 500" in err


def test_offline_without_cache(wp_site: Path) -> None:
    code, _, err = run(["scan", str(wp_site), "--offline"])
    assert code == 3 and "no cached" in err


def test_argparse_error_returns_2() -> None:
    assert run(["scan", "--format", "xml"])[0] == 2
