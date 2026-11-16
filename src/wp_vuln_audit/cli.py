"""Command-line interface.

Exit codes:

* 0 - no finding at or above ``--fail-on``
* 1 - at least one finding at or above ``--fail-on`` (with ``--baseline``: a new one,
  unless ``--fail-scope all``)
* 2 - usage error or unreadable input
* 3 - the vulnerability feed could not be loaded
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from ._version import __version__
from .audit import AuditOptions, AuditResult, audit
from .baseline import Baseline, BaselineError, compare
from .cache import DEFAULT_BASE_URL, FEED_VARIANTS, FeedError, FeedSource, FetchResult, default_cache_dir
from .feed import SEVERITIES, Feed, FeedFormatError
from .http import RateLimiter, Transport
from .ignore import DEFAULT_IGNORE_FILE, IgnoreError, IgnoreList
from .inventory import Component, Inventory
from .remote import RemoteOptions, RemoteScanner
from .report import FORMATS, render, render_json
from .versions import normalize_version
from .wp_local import WordPressNotFound, scan_local
from .wpcli import WpCliError, parse_combined, parse_core_version, parse_list

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_FEED = 3

FAIL_ON = ("any", "low", "medium", "high", "critical", "never")


class UsageError(Exception):
    pass


def _add_feed_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("feed")
    g.add_argument("--feed", choices=FEED_VARIANTS, default="production", help="feed variant (default: production)")
    g.add_argument("--feed-file", metavar="FILE", help="use a downloaded feed JSON file instead of the API")
    g.add_argument(
        "--api-key",
        metavar="KEY",
        help="Wordfence Intelligence API key (default: $WORDFENCE_API_KEY)",
    )
    g.add_argument("--cache-dir", metavar="DIR", help=f"feed cache directory (default: {default_cache_dir()})")
    g.add_argument("--max-age", type=float, default=6.0, metavar="HOURS", help="reuse the cache this long (default: 6)")
    g.add_argument("--refresh", action="store_true", help="revalidate the cached feed now")
    g.add_argument("--offline", action="store_true", help="never download; use the cache only")
    g.add_argument("--base-url", default=DEFAULT_BASE_URL, help=argparse.SUPPRESS)


def _add_filter_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("filtering")
    g.add_argument("--min-severity", choices=SEVERITIES[1:], help="hide findings below this CVSS rating")
    g.add_argument("--min-cvss", type=float, metavar="SCORE", help="hide findings with a CVSS score below SCORE")
    u = g.add_mutually_exclusive_group()
    u.add_argument(
        "--include-unscored",
        dest="include_unscored",
        action="store_true",
        default=None,
        help="keep findings without a CVSS score even when a severity filter is set",
    )
    u.add_argument(
        "--exclude-unscored", dest="include_unscored", action="store_false", help="drop findings without a CVSS score"
    )
    g.add_argument("--include-informational", action="store_true", help="include informational records")
    g.add_argument("--ignore-file", metavar="FILE", help=f"ignore rules (default: ./{DEFAULT_IGNORE_FILE} if present)")
    g.add_argument("--no-ignore-file", action="store_true", help="do not read an ignore file")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=(*FORMATS, "md"), default="text", help="report format (default: text)")
    g.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of standard output")
    g.add_argument("--show-ignored", action="store_true", help="list ignored findings in text and Markdown reports")
    g.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="colour text output")
    g.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default="any",
        help="exit 1 when a finding is at or above this severity (default: any)",
    )
    b = p.add_argument_group("baseline")
    b.add_argument(
        "--baseline",
        metavar="FILE",
        help="earlier JSON or SARIF report; findings in it are 'unchanged', the rest 'new'",
    )
    b.add_argument(
        "--fail-scope",
        choices=("new", "all"),
        default="new",
        help="with --baseline: let only new findings (default) or all findings trigger --fail-on",
    )
    b.add_argument("--new-only", action="store_true", help="with --baseline: report new findings only")
    b.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="also write the full JSON report to FILE for the next --baseline run",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-vuln-audit",
        description="Check WordPress core, plugin and theme versions against the Wordfence Intelligence feed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="audit a WordPress install, WP-CLI output or a remote site")
    scan.add_argument("path", nargs="?", help="WordPress root directory")
    src = scan.add_argument_group("inputs")
    src.add_argument("--content-dir", metavar="DIR", help="wp-content location when it is not inside PATH")
    src.add_argument("--no-mu-plugins", action="store_true", help="skip wp-content/mu-plugins")
    src.add_argument("--wp-cli", metavar="FILE", help='combined {"core","plugins","themes"} JSON, or "-" for stdin')
    src.add_argument("--plugins-json", metavar="FILE", help="output of `wp plugin list --format=json`")
    src.add_argument("--themes-json", metavar="FILE", help="output of `wp theme list --format=json`")
    src.add_argument(
        "--core-version", metavar="VERSION", help="WordPress version, or a file with `wp core version` output"
    )
    src.add_argument("--url", metavar="URL", help="detect versions on a live site (needs --allow-remote)")
    src.add_argument("--allow-remote", action="store_true", help="confirm that remote requests to --url are allowed")
    src.add_argument("--remote-plugin", action="append", default=[], metavar="SLUG", help="also probe this plugin")
    src.add_argument("--remote-theme", action="append", default=[], metavar="SLUG", help="also probe this theme")
    src.add_argument("--no-discover", action="store_true", help="only probe the slugs given with --remote-*")
    src.add_argument(
        "--rate-limit", type=float, default=1.0, metavar="SECONDS", help="delay between requests (default: 1)"
    )
    src.add_argument("--max-requests", type=int, default=40, metavar="N", help="request budget for --url (default: 40)")
    _add_feed_args(scan)
    _add_filter_args(scan)
    _add_output_args(scan)

    check = sub.add_parser("check", help="check one component version")
    check.add_argument("type", choices=("core", "plugin", "theme"))
    check.add_argument("slug", help="slug (use 'wordpress' for core)")
    check.add_argument("version", nargs="?", help="installed version (for core the slug can be omitted)")
    _add_feed_args(check)
    _add_filter_args(check)
    _add_output_args(check)

    inv = sub.add_parser("inventory", help="list detected components without checking them")
    inv.add_argument("path", help="WordPress root directory")
    inv.add_argument("--content-dir", metavar="DIR")
    inv.add_argument("--no-mu-plugins", action="store_true")
    inv.add_argument("-f", "--format", choices=("text", "json"), default="text")

    feed = sub.add_parser("feed", help="download or inspect the cached feed")
    feed.add_argument("action", choices=("update", "info", "clear"))
    _add_feed_args(feed)

    return parser


# --------------------------------------------------------------------------- helpers


def _read_input(path: str, stdin: TextIO) -> str:
    if path == "-":
        return stdin.read()
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _feed_source(args: argparse.Namespace, transport: Transport | None) -> FeedSource:
    api_key = args.api_key or os.environ.get("WORDFENCE_API_KEY") or None
    return FeedSource(
        args.feed,
        api_key=api_key,
        base_url=args.base_url,
        cache_dir=args.cache_dir,
        transport=transport,
        max_age=max(0.0, args.max_age) * 3600,
    )


def load_feed(args: argparse.Namespace, transport: Transport | None) -> FetchResult:
    if args.feed_file:
        try:
            feed = Feed.from_file(args.feed_file)
        except OSError as exc:
            raise FeedError(f"cannot read {args.feed_file}: {exc.strerror or exc}") from exc
        return FetchResult(feed, "file", None, args.feed_file)
    return _feed_source(args, transport).load(refresh=args.refresh, offline=args.offline)


def _ignore_list(args: argparse.Namespace) -> IgnoreList | None:
    if args.no_ignore_file:
        return None
    if args.ignore_file:
        try:
            return IgnoreList.load(args.ignore_file)
        except OSError as exc:
            raise UsageError(f"cannot read ignore file {args.ignore_file}: {exc.strerror or exc}") from exc
    candidates = [Path.cwd() / DEFAULT_IGNORE_FILE]
    path = getattr(args, "path", None)
    if path:
        candidates.append(Path(path) / DEFAULT_IGNORE_FILE)
    for c in candidates:
        if c.is_file():
            return IgnoreList.load(c)
    return None


def _options(args: argparse.Namespace) -> AuditOptions:
    return AuditOptions(
        min_severity=args.min_severity or "unknown",
        min_cvss=args.min_cvss,
        include_unscored=args.include_unscored,
        include_informational=args.include_informational,
        ignore=_ignore_list(args),
    )


def build_inventory(
    args: argparse.Namespace,
    stdin: TextIO,
    transport: Transport | None = None,
    limiter: RateLimiter | None = None,
) -> Inventory:
    inv = Inventory()
    targets: list[str] = []
    if args.path:
        local = scan_local(args.path, content_dir=args.content_dir, include_mu=not args.no_mu_plugins)
        inv.extend(local)
        targets.append(local.target)
    if args.wp_cli:
        combined = parse_combined(_read_input(args.wp_cli, stdin), location=args.wp_cli)
        inv.extend(combined)
        targets.append(f"wp-cli:{args.wp_cli}")
    if args.plugins_json:
        for c in parse_list(_read_input(args.plugins_json, stdin), "plugin", args.plugins_json):
            inv.add(c)
        targets.append(f"wp-cli:{args.plugins_json}")
    if args.themes_json:
        for c in parse_list(_read_input(args.themes_json, stdin), "theme", args.themes_json):
            inv.add(c)
        targets.append(f"wp-cli:{args.themes_json}")
    if args.core_version:
        raw = args.core_version
        if raw == "-" or Path(raw).is_file():
            version = parse_core_version(_read_input(raw, stdin))
        else:
            version = normalize_version(raw)
        if not version:
            raise UsageError(f"--core-version: cannot read a version from {raw!r}")
        inv.add(Component("core", "wordpress", version, "WordPress", "wp core version", source="wp-cli"))
        targets.append(f"core {version}")
    if args.url:
        if not args.allow_remote:
            raise UsageError("--url sends requests to that site; add --allow-remote to confirm")
        if args.max_requests < 1 or args.rate_limit < 0:
            raise UsageError("--max-requests must be >= 1 and --rate-limit >= 0")
        opts = RemoteOptions(
            interval=args.rate_limit,
            max_requests=args.max_requests,
            discover=not args.no_discover,
            plugins=list(args.remote_plugin),
            themes=list(args.remote_theme),
        )
        scanner = RemoteScanner(args.url, opts, transport=transport, limiter=limiter)
        remote = scanner.scan()
        inv.extend(remote)
        targets.append(remote.target)
    elif args.remote_plugin or args.remote_theme:
        raise UsageError("--remote-plugin and --remote-theme need --url")
    if not targets:
        raise UsageError(
            "nothing to scan: give a WordPress PATH, --wp-cli, --plugins-json, --themes-json, --core-version or --url"
        )
    inv.target = ", ".join(targets)
    return inv


def _feed_info(fr: FetchResult) -> dict[str, object]:
    info: dict[str, object] = {"status": fr.status, "records": len(fr.feed)}
    if fr.meta is not None:
        info["url"] = fr.meta.url
        info["etag"] = fr.meta.etag
        info["last_modified"] = fr.meta.last_modified
    if fr.status == "file":
        info["file"] = fr.message
    return info


def _use_color(choice: str, stream: TextIO) -> bool:
    if choice == "always":
        return True
    if choice == "never" or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _emit(result: AuditResult, args: argparse.Namespace, stdout: TextIO) -> None:
    fmt = "markdown" if args.format == "md" else args.format
    to_file = bool(args.output)
    text = render(result, fmt, color=not to_file and _use_color(args.color, stdout), show_ignored=args.show_ignored)
    if to_file:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        stdout.write(text)


def _load_baseline(args: argparse.Namespace, stderr: TextIO) -> Baseline | None:
    if not args.baseline:
        if args.new_only:
            raise UsageError("--new-only needs --baseline")
        return None
    path = Path(args.baseline)
    if not path.exists() and args.write_baseline and Path(args.write_baseline).resolve() == path.resolve():
        # First run of a "--baseline F --write-baseline F" job: start from an empty baseline.
        stderr.write(f"wp-vuln-audit: baseline {args.baseline} does not exist yet; every finding is new\n")
        return Baseline([], args.baseline)
    try:
        return Baseline.load(path)
    except BaselineError as exc:
        raise UsageError(f"--baseline: {exc}") from exc


def _run_audit(
    inv: Inventory, args: argparse.Namespace, stdout: TextIO, stderr: TextIO, transport: Transport | None
) -> int:
    options = _options(args)
    baseline = _load_baseline(args, stderr)
    fr = load_feed(args, transport)
    if fr.message and fr.status != "file":
        stderr.write(f"wp-vuln-audit: {fr.message}\n")
    if (args.min_severity or args.min_cvss is not None) and not fr.feed.has_cvss:
        stderr.write("wp-vuln-audit: warning: this feed has no CVSS scores (use --feed production)\n")
    result = audit(fr.feed, inv, options)
    info = _feed_info(fr)
    info["variant"] = "file" if fr.status == "file" else args.feed
    result.feed_info = info
    if baseline is not None:
        comparison = compare(result, baseline)
        stderr.write(
            f"wp-vuln-audit: baseline: {len(comparison.new)} new, {len(comparison.unchanged)} unchanged, "
            f"{len(comparison.resolved)} resolved\n"
        )
    if args.write_baseline:
        # Always the complete result, so --new-only does not shrink the next baseline.
        Path(args.write_baseline).write_text(render_json(result), encoding="utf-8")
        stderr.write(f"wp-vuln-audit: wrote baseline to {args.write_baseline}\n")
    fails = result.fails(args.fail_on, new_only=args.fail_scope == "new")
    if args.new_only and result.baseline is not None:
        result.findings = list(result.baseline.new)
    _emit(result, args, stdout)
    if args.output:
        stderr.write(f"wp-vuln-audit: wrote {args.format} report to {args.output}\n")
    return EXIT_FINDINGS if fails else EXIT_OK


# --------------------------------------------------------------------------- commands


def cmd_scan(args, stdin, stdout, stderr, transport, limiter) -> int:
    inv = build_inventory(args, stdin, transport, limiter)
    return _run_audit(inv, args, stdout, stderr, transport)


def cmd_check(args, stdin, stdout, stderr, transport, limiter) -> int:
    if args.type == "core":
        version = args.version or args.slug
        slug = "wordpress"
    else:
        if not args.version:
            raise UsageError("check: VERSION is required for plugins and themes")
        version, slug = args.version, args.slug.lower()
    v = normalize_version(version)
    if not v:
        raise UsageError(f"check: invalid version {version!r}")
    inv = Inventory([Component(args.type, slug, v, slug, "", source="cli")], target=f"{args.type} {slug} {v}")
    return _run_audit(inv, args, stdout, stderr, transport)


def cmd_inventory(args, stdin, stdout, stderr, transport, limiter) -> int:
    inv = scan_local(args.path, content_dir=args.content_dir, include_mu=not args.no_mu_plugins)
    if args.format == "json":
        payload = {
            "target": inv.target,
            "components": [c.to_dict() for c in inv.components],
            "warnings": inv.warnings,
        }
        stdout.write(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK
    for c in inv.components:
        notes = f"  ({'; '.join(c.notes)})" if c.notes else ""
        stdout.write(f"{c.type:<7} {c.slug:<40} {c.version or '?':<14} {c.location}{notes}\n")
    for w in inv.warnings:
        stderr.write(f"warning: {w}\n")
    return EXIT_OK


def cmd_feed(args, stdin, stdout, stderr, transport, limiter) -> int:
    source = _feed_source(args, transport)
    if args.action == "clear":
        removed = source.clear()
        stdout.write(f"{'removed' if removed else 'no'} cached {args.feed} feed in {source.cache_dir}\n")
        return EXIT_OK
    if args.action == "info":
        meta = source.read_meta()
        if meta is None:
            stdout.write(f"no cached {args.feed} feed in {source.cache_dir}\n")
            return EXIT_FEED
        feed = Feed.from_file(str(source.data_path))
        stdout.write(
            json.dumps(
                {
                    "variant": args.feed,
                    "path": str(source.data_path),
                    "records": len(feed),
                    "with_cvss": sum(1 for v in feed if v.cvss),
                    **meta.to_dict(),
                },
                indent=2,
            )
            + "\n"
        )
        return EXIT_OK
    fr = source.load(refresh=True)
    if fr.message:
        stderr.write(f"wp-vuln-audit: {fr.message}\n")
    stdout.write(f"{args.feed} feed: {fr.status}, {len(fr.feed)} records ({source.data_path})\n")
    return EXIT_OK if fr.status in ("downloaded", "not-modified", "cached") else EXIT_FEED


COMMANDS = {"scan": cmd_scan, "check": cmd_check, "inventory": cmd_inventory, "feed": cmd_feed}


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    transport: Transport | None = None,
    limiter: RateLimiter | None = None,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if isinstance(exc.code, int) else EXIT_USAGE
    if not args.command:
        parser.print_help(stdout)
        return EXIT_USAGE
    try:
        return COMMANDS[args.command](args, stdin, stdout, stderr, transport, limiter)
    except (FeedError, FeedFormatError) as exc:
        stderr.write(f"wp-vuln-audit: feed error: {exc}\n")
        return EXIT_FEED
    except (UsageError, WpCliError, IgnoreError, WordPressNotFound, ValueError) as exc:
        stderr.write(f"wp-vuln-audit: {exc}\n")
        return EXIT_USAGE
    except OSError as exc:
        stderr.write(f"wp-vuln-audit: {exc}\n")
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
