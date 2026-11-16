# wp-vuln-audit

[![CI](https://github.com/saizul/wp-vuln-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/wp-vuln-audit/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Check the WordPress core, plugin and theme versions of a site against the free
[Wordfence Intelligence](https://www.wordfence.com/threat-intel/) vulnerability feed, and fail the build when something
you run is known to be vulnerable.

Most WordPress sites get compromised through an outdated plugin with a public advisory. `wp-vuln-audit` reads the
versions straight from the files (or from WP-CLI, or from a live site if you allow it), compares them with the
`affected_versions` ranges in the feed using the same rules as PHP's `version_compare()`, and reports what is affected,
how bad it is (CVSS) and which version fixes it, as text, JSON, Markdown or SARIF for GitHub code scanning.

```console
$ wp-vuln-audit scan /var/www/example.com --min-severity medium
Scanned /var/www/example.com: core yes, 14 plugin(s), 3 theme(s)
Feed: production (31842 records, cached)

plugin example-forms 2.0.3 [wp-content/plugins/example-forms/example-forms.php]
  CRITICAL 9.8  Example Forms <= 2.4.1 - Unauthenticated SQL Injection CVE-2026-20001
                affected <= 2.4.1; fixed in 2.4.2
                https://www.wordfence.com/threat-intel/vulnerabilities/id/...
  MEDIUM 5.3    Example Forms 2.0.0 - 2.0.5 - Cross-Site Request Forgery CVE-2026-20002
                affected >= 2.0.0, <= 2.0.5; fixed in 2.0.6
                https://www.wordfence.com/threat-intel/vulnerabilities/id/...
WordPress 6.4.2 [wp-includes/version.php]
  MEDIUM 6.4    WordPress Core <= 6.4.2 - Authenticated Stored Cross-Site Scripting CVE-2026-10001
                affected <= 6.4.2; fixed in 6.4.3
                https://www.wordfence.com/threat-intel/vulnerabilities/id/...

3 vulnerabilities in 2 component(s): 1 critical, 2 medium
```

(The plugin names and CVE numbers in this README and in `examples/` are made up.)

It is a command-line tool and a Python library with **no runtime dependencies** (standard library only), for Python
3.10 and newer.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Docker image](#docker-image)
- [Getting a Wordfence API key](#getting-a-wordfence-api-key)
- [Usage](#usage)
- [Configuration](#configuration)
- [How matching works](#how-matching-works)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Library use](#library-use)
- [Examples](#examples)
- [Testing](#testing)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Three ways to build the inventory**
  - a **WordPress directory**: `$wp_version` from `wp-includes/version.php`, plugin headers from the main file of each
    plugin directory, single-file plugins, must-use plugins, and `style.css` headers of each theme. Headers are read the
    way WordPress' `get_file_data()` reads them (first 8 KiB, one header per line). No PHP is run.
  - **WP-CLI output**: `wp plugin list --format=json`, `wp theme list --format=json` and `wp core version`, or one
    combined JSON document. Drop-ins are skipped, PHP notices before the JSON are tolerated.
  - a **remote site** (opt-in with `--allow-remote`): the generator tag, `/feed/` or core asset `?ver=` for core,
    `readme.txt` for plugins and `style.css` for themes found in the page source or named on the command line.
    Requests are rate-limited, capped, same-host only and `GET` only.
- **Version matching like WordPress**
  - a port of PHP's `version_compare()`: `1.0rc1 < 1.0 < 1.0pl1`, `1.0-beta == 1.0beta`, `5.2 < 5.2.0`, `1.10 > 1.9`
  - every bound of the feed's `affected_versions` objects (`from_version`, `from_inclusive`, `to_version`,
    `to_inclusive`, `*` for "no bound"), with the range label (`* - 1.2.3`, `1.0 - 2.0`, `<= 1.1`, `1.3.0`) as a
    fallback when the bounds are missing
  - "fixed in": the lowest `patched_versions` entry above the installed version that is not itself affected
- **Feed handling**
  - production (with CVSS, CWE, CVE and remediation) or scanner feed from the v3 API
  - on-disk cache with `ETag` / `If-None-Match` and `Last-Modified` / `If-Modified-Since` revalidation, a
    configurable maximum age, gzip transfer, atomic writes and validation before the cache is replaced
  - falls back to the cached copy when the API is unreachable, and `--offline` for air-gapped runs
  - `--feed-file` for a feed you downloaded yourself
- **Filtering**: `--min-severity` (CVSS rating), `--min-cvss`, records without a score kept or dropped explicitly,
  informational records hidden unless asked for, and an **ignore file** with ids, CVEs, components, versions, reasons and
  expiry dates.
- **Reports**: text (grouped by component, coloured on a terminal), JSON, Markdown (for PR comments, chat or e-mail) and
  **SARIF 2.1.0** with `security-severity`, CWE tags and stable fingerprints for GitHub code scanning.
- **CI friendly**: `--fail-on` threshold, distinct exit codes for "vulnerable", "bad input" and "feed problem".
- **Baselines**: compare with an earlier JSON or SARIF report, mark findings as new or unchanged, list resolved ones,
  and fail the build on new findings only.

## Installation

The project is not on PyPI yet. Install it from GitHub or from a checkout:

```console
$ pip install "git+https://github.com/saizul/wp-vuln-audit@v0.1.0"
```

```console
$ git clone https://github.com/saizul/wp-vuln-audit.git
$ cd wp-vuln-audit
$ python -m pip install .
```

This installs the `wp-vuln-audit` command. `python -m wp_vuln_audit` works too.

## Docker image

A multi-arch image (linux/amd64, linux/arm64) is published to GitHub Packages:

```bash
docker pull ghcr.io/saizul/wp-vuln-audit:latest

# Scan a site on the host; keep the feed cache in a named volume between runs.
docker run --rm \
  -e WORDFENCE_API_KEY \
  -v wp-vuln-audit-cache:/cache \
  -v /var/www/example.com:/work:ro \
  ghcr.io/saizul/wp-vuln-audit:latest scan . --min-severity medium
```

Mount the site (or the folder with your WP-CLI JSON files) at `/work`, the working directory of the image. The feed
cache lives in `/cache`. Release images are also tagged with the version (`ghcr.io/saizul/wp-vuln-audit:0.1.0`) and
every build with its commit SHA. The container runs as an unprivileged user (uid 10001), so a read-only mount is enough.

## Getting a Wordfence API key

Version 3 of the Wordfence Intelligence feed needs a free API key (versions 1 and 2 did not, and were scheduled to
be switched off in March 2026). Create a free Wordfence account, open the account's integrations section and generate an API key for the
vulnerability data feed, then:

```bash
export WORDFENCE_API_KEY=your-api-key-here
wp-vuln-audit feed update
```

The key is sent as `Authorization: Bearer <key>` to
`https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production` (or `/scanner`). Read and follow the
[Wordfence Intelligence terms](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/); the feed
records carry copyright and licence information, and reports should keep the link back to Wordfence.

No key? Pass a feed you have downloaded with `--feed-file feed.json`.

## Usage

### scan a WordPress directory

```console
$ wp-vuln-audit scan /var/www/example.com
$ wp-vuln-audit scan . --content-dir ../shared/wp-content      # wp-content outside the root
$ wp-vuln-audit scan . --no-mu-plugins
$ wp-vuln-audit scan . --format sarif --output wp-vuln-audit.sarif --fail-on high
```

### scan from WP-CLI output

Useful when the files are on another server, or in a container you can reach with `wp` but not mount:

```console
$ wp plugin list --format=json > plugins.json
$ wp theme list --format=json > themes.json
$ wp core version > core.txt
$ wp-vuln-audit scan --plugins-json plugins.json --themes-json themes.json --core-version core.txt

$ wp plugin list --format=json | wp-vuln-audit scan --plugins-json - --core-version 6.6.2
$ wp-vuln-audit scan --wp-cli site.json        # {"core": "6.6.2", "plugins": [...], "themes": [...]}
```

`wp plugin list` also reports inactive plugins. They are checked too: an inactive plugin's files can still be reached
directly on many setups.

### scan a remote site (opt-in)

```console
$ wp-vuln-audit scan --url https://www.example.com --allow-remote
$ wp-vuln-audit scan --url https://www.example.com --allow-remote \
    --remote-plugin woocommerce --remote-plugin contact-form-7 --remote-theme astra \
    --rate-limit 2 --max-requests 20
$ wp-vuln-audit scan --url https://www.example.com --allow-remote --no-discover --remote-plugin akismet
```

Only scan sites you own or are allowed to test. See [Limitations](#limitations) for how reliable remote versions are.

### check one component

```console
$ wp-vuln-audit check plugin contact-form-7 5.3.1
$ wp-vuln-audit check theme astra 4.0.0 --format json
$ wp-vuln-audit check core 6.4.2
```

### compare with a baseline

Adopting the tool on a site with known, accepted issues? Record them once and let CI fail only when something new
appears:

```console
$ wp-vuln-audit scan . --format json --output baseline.json --fail-on never     # once, commit or store the file
$ wp-vuln-audit scan . --baseline baseline.json --fail-on high                  # later runs
wp-vuln-audit: baseline: 1 new, 4 unchanged, 1 resolved
```

A finding is identified by component type, slug and Wordfence vulnerability id; the installed version is not part of
the key, so updating a plugin to a release that is still affected by the same advisory does not make it "new". Both a
JSON report and a SARIF report can be the baseline, and ignored findings in a JSON baseline count as known.

- new findings are marked `[new]` in text, **New:** in Markdown, `"baseline_state": "new"` in JSON and
  `baselineState` in SARIF; baseline entries that are no longer reported are listed as resolved
- `--fail-on` counts only new findings; `--fail-scope all` makes every finding count again
- `--new-only` leaves unchanged findings out of the report
- `--write-baseline FILE` also writes the complete JSON report to `FILE` (unaffected by `--new-only`). When
  `--baseline` and `--write-baseline` name the same file and it does not exist yet, the run starts from an empty
  baseline, which makes a rolling baseline a single command:

```console
$ wp-vuln-audit scan . --baseline state/wp.json --write-baseline state/wp.json --new-only --format markdown
```

### list what was found

```console
$ wp-vuln-audit inventory /var/www/example.com
core    wordpress                                6.4.2          wp-includes/version.php
plugin  example-forms                            2.0.3          wp-content/plugins/example-forms/example-forms.php
theme   demo-theme                               1.2            wp-content/themes/demo-theme/style.css
```

### manage the feed cache

```console
$ wp-vuln-audit feed update            # conditional download now
$ wp-vuln-audit feed info              # path, size, ETag, Last-Modified, record count
$ wp-vuln-audit feed clear
$ wp-vuln-audit feed update --feed scanner
```

## Configuration

| Option | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--api-key KEY` | `WORDFENCE_API_KEY` | none | Wordfence Intelligence v3 API key |
| `--feed production\|scanner` | | `production` | feed variant; only production has CVSS scores |
| `--feed-file FILE` | | | use this feed JSON instead of the API |
| `--cache-dir DIR` | `WP_VULN_AUDIT_CACHE`, `XDG_CACHE_HOME` | `~/.cache/wp-vuln-audit` | where the feed is cached |
| `--max-age HOURS` | | `6` | reuse the cache without asking the API |
| `--refresh` / `--offline` | | | revalidate now / never use the network |
| `--min-severity LEVEL` | | none | `none`, `low`, `medium`, `high` or `critical` |
| `--min-cvss SCORE` | | none | drop findings scored below `SCORE` |
| `--include-unscored` / `--exclude-unscored` | | see below | records without a CVSS score |
| `--include-informational` | | off | include records Wordfence marks as informational |
| `--ignore-file FILE` | | `./.wpvulnignore`, then `<PATH>/.wpvulnignore` | ignore rules |
| `--no-ignore-file` | | | do not read an ignore file |
| `-f, --format` | | `text` | `text`, `json`, `markdown` (`md`) or `sarif` |
| `-o, --output FILE` | | stdout | write the report to a file |
| `--fail-on LEVEL` | | `any` | `any`, `low`, `medium`, `high`, `critical` or `never` |
| `--baseline FILE` | | none | earlier JSON or SARIF report to compare with |
| `--fail-scope new\|all` | | `new` | with `--baseline`: which findings `--fail-on` counts |
| `--new-only` | | off | with `--baseline`: report new findings only |
| `--write-baseline FILE` | | none | also write the full JSON report to `FILE` |
| `--color auto\|always\|never` | `NO_COLOR` | `auto` | colours in text output |
| `--rate-limit SECONDS` | | `1` | delay between remote requests |
| `--max-requests N` | | `40` | request budget of a remote scan |

Records without a CVSS score (all records of the scanner feed, and a few of the production feed) are kept when no
severity or score filter is set. With a filter they are dropped, unless you add `--include-unscored`.

### Ignore file

```text
# .wpvulnignore - one rule per line, "#" starts a comment
00000000-0000-4000-8000-000000000003                 # a Wordfence vulnerability id
CVE-2026-20002 reason="admin-only CSRF, WAF rule in place"
plugin:demo-slider                                   # every finding for a plugin
plugin:demo-slider@4.2                               # ... or only for one installed version
theme:demo-theme@1.2
core@6.4.2
CVE-2026-20003 expires=2026-12-31 reason="vendor fix scheduled"
```

Expired rules stop applying and print a warning, so accepted risks get reviewed. `--show-ignored` lists ignored findings
in text and Markdown reports; the JSON report always contains them under `ignored`.

## How matching works

1. Each component is looked up by type (`core`, `plugin`, `theme`) and slug. For plugins and themes the slug is the
   directory name, which is the WordPress.org slug for anything installed from the directory. Core is `wordpress`.
2. For every software entry of every record for that slug, each `affected_versions` range is tested:
   `from_version` (`*` = no lower bound) with `from_inclusive`, and `to_version` (`*` = no upper bound) with
   `to_inclusive`. A record is reported once per component even when several ranges match.
3. Versions are compared like PHP's `version_compare()`, which is what WordPress itself uses. That matters for
   pre-releases and odd versions: `6.5-RC1` is older than `6.5`, `2.0.0-beta1` older than `2.0.0`, and `5.2` older
   than `5.2.0`.
4. "Fixed in" is the lowest version in `patched_versions` that is newer than the installed one and outside every
   affected range. When there is none the feed's `remediation` text is shown, or "no fix available".

Components whose version could not be read are listed as "not checked" rather than silently passing.

## Output formats

- **text** (default): grouped by component, most severe first, with the affected range, the fix and the advisory link.
- **json**: `schema_version`, a `summary` (counts by severity, highest severity), every component, `findings`,
  `ignored`, `unchecked` and `warnings`. Each finding has the id, title, CVE, CVSS vector and score, CWE, affected
  range, fix, remediation, advisory URL and references. With `--baseline`, findings carry `baseline_state` and a
  `baseline` object holds the new, unchanged and resolved counts and the resolved entries.
- **markdown**: a table for pull request comments, issues, Slack or e-mail.
- **sarif**: SARIF 2.1.0. Every vulnerability is a rule with `security-severity` set to its CVSS score, so GitHub code
  scanning shows Critical / High / Medium / Low; results point at the file the version was read from and carry a
  `partialFingerprints` value so alerts are tracked across runs. See
  [examples/github-actions-wp-vuln-audit.yml](examples/github-actions-wp-vuln-audit.yml).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | no finding at or above `--fail-on` (or `--fail-on never`) |
| 1 | at least one finding at or above `--fail-on` (with `--baseline`: a new one, unless `--fail-scope all`) |
| 2 | usage error, unreadable input, not a WordPress directory, invalid ignore file or baseline |
| 3 | the feed could not be loaded (no API key, rejected key, download failed without a cache, invalid JSON) |

## Library use

```python
from wp_vuln_audit import AuditOptions, Feed, FeedSource, IgnoreList, audit, render, scan_local

feed = FeedSource("production", api_key="your-api-key-here").load().feed
# or: feed = Feed.from_file("feed.json")

inventory = scan_local("/var/www/example.com")
result = audit(feed, inventory, AuditOptions(min_severity="medium", ignore=IgnoreList.load(".wpvulnignore")))

for f in result.findings:
    print(f.component.slug, f.component.version, f.vulnerability.cve, f.severity, f.fixed_in)

print(render(result, "markdown"))
```

`compare_versions()`, `parse_affected_versions()`, `parse_list()` (WP-CLI) and `RemoteScanner` are public too. Every
network call goes through a transport callable that you can replace, for tests or for a proxy.

## Examples

The [examples](examples) folder has:

- `sample-site/`: a tiny fake WordPress tree, and `feed-sample.json`, a made-up feed slice in the v3 format, so you can
  try every command without an API key: `wp-vuln-audit scan examples/sample-site --feed-file examples/feed-sample.json`
- `wp-cli-site.json` and `plugins.json`: WP-CLI style inputs
- `wpvulnignore.example`: an ignore file
- `github-actions-wp-vuln-audit.yml`: daily scan with SARIF upload to code scanning
- `server-cron.sh`: nightly WP-CLI based check that mails a Markdown report
- `library_usage.py`: the Python API

## Testing

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest
$ ruff check . && ruff format --check .
```

The suite uses fixture feed slices in `tests/fixtures/` (production and scanner layouts), fake WordPress trees built
in temporary directories, a fake transport for every API and remote call, and a local HTTP server for the real
transport. It never touches the internet. CI runs it on Python 3.10 to 3.13.

## Security notes

- **The API key is a secret.** Prefer the `WORDFENCE_API_KEY` environment variable (or a CI secret) over `--api-key`,
  which other users on the machine can see in the process list. The key is only sent to the feed URL.
- **Nothing is executed.** Plugin and theme headers are read as text from the first 8 KiB of each file; `version.php`
  is matched with a regular expression, never included.
- **Remote scans are opt-in** and only send `GET` requests to the host you give, with a request budget, a delay
  between requests, a timeout and a response size cap. URLs with embedded credentials are refused. Only scan sites you
  are allowed to test.
- **The cache** is written atomically and only replaced after the new download parsed as a valid feed. Point
  `--cache-dir` at a directory only your user can write to.
- A clean report means "no known vulnerability for the versions found", not "secure". Custom code, premium plugins
  missing from the feed, server configuration and weak passwords are out of scope.

Report security problems in this tool as described in [SECURITY.md](SECURITY.md).

## Limitations

- **Coverage is the feed's coverage.** Plugins and themes that are not in the Wordfence Intelligence database
  (custom, many premium ones) are never reported.
- **Slugs are directory names.** A plugin installed in a renamed directory, or a premium plugin whose directory name
  collides with a different WordPress.org plugin, is matched under that directory name.
- **Remote versions are guesses.** `readme.txt` may be out of date or removed, the generator tag can be hidden or faked,
  `style.css` may be cached by a CDN, and plugins that load no assets on the home page are not discovered. Remote
  results are marked `source: remote`; use a local or WP-CLI scan when you can.
- **Must-use plugins and drop-ins** rarely exist in the feed under their file names; must-use plugins are checked by file
  name, drop-ins are skipped.
- **The feed is large** (hundreds of MiB for production). The first download takes a while and the parsed feed needs
  memory; later runs revalidate with `ETag` / `Last-Modified` when the API sends them, or reuse the cache within
  `--max-age`.
- Whether the Wordfence API answers conditional requests with `304 Not Modified` is up to the API. When it does not, the
  cache still avoids downloads inside `--max-age`.
- Version strings that are not version-like (for example `trunk` or `dev`) are compared with PHP rules and may give
  surprising results.

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) - Copyright (c) 2026 Saizul Amin. Vulnerability data is provided by Wordfence under its own terms.
