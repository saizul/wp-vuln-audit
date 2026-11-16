# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Baselines: `--baseline FILE` compares a scan with an earlier JSON or SARIF report. Findings are keyed by
  component type, slug and vulnerability id (not the installed version) and marked new or unchanged in every
  report format (`[new]`, **New:**, `baseline_state`, SARIF `baselineState`); baseline entries that are no longer
  reported are listed as resolved.
- `--fail-scope new|all`, `--new-only` and `--write-baseline FILE`, including a rolling baseline when
  `--baseline` and `--write-baseline` name the same, not yet existing file.
- `Baseline`, `BaselineComparison`, `BaselineError` and `compare()` in the Python API.
- SARIF results carry a `severity` property.

### Changed

- With `--baseline`, `--fail-on` counts only findings that are not in the baseline (use `--fail-scope all` for the
  previous behaviour). Runs without `--baseline` are unchanged.

## [0.1.0] - 2026-11-13

First public release.

### Added

- Wordfence Intelligence v3 feed client for the production and scanner feeds, with
  API key authentication, gzip transfer, an on-disk cache, `ETag` /
  `If-Modified-Since` revalidation, a maximum cache age, offline mode, fallback to
  the cached copy when the API is unavailable, and `--feed-file` for local copies.
- Feed parser for the v3 record layout: software entries, `affected_versions`
  bounds, patched versions, remediation, CVSS, CWE, CVE, references and
  informational records.
- Port of PHP's `version_compare()` and range matching for `from_version` /
  `from_inclusive` / `to_version` / `to_inclusive` with `*` bounds, plus parsing of
  range labels (`* - 1.2`, `1.0 - 2.0`, `<= 1.1`, single versions).
- Local inventory from a WordPress directory: core from `wp-includes/version.php`,
  plugin headers (directories, single-file and must-use plugins) and theme
  `style.css` headers, read like `get_file_data()`.
- WP-CLI inputs: `wp plugin list`, `wp theme list`, `wp core version` and a
  combined JSON document.
- Opt-in remote detection from the generator tag, `/feed/`, core asset versions,
  `readme.txt` and `style.css`, with rate limiting, a request budget and
  same-host requests only.
- Severity and CVSS score filters, informational and unscored record handling,
  and an ignore file with ids, CVEs, components, versions, reasons and expiry dates.
- Text, JSON, Markdown and SARIF 2.1.0 reports, and `--fail-on` exit codes for CI.
- `scan`, `check`, `inventory` and `feed` commands.
- Docker image definition and publishing workflow.
- Test suite of 312 tests with fixture feed slices and fake WordPress trees.

[Unreleased]: https://github.com/saizul/wp-vuln-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/wp-vuln-audit/releases/tag/v0.1.0
