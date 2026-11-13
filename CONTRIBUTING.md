# Contributing

Thanks for taking the time to improve wp-vuln-audit. Bug reports, matching
fixes, new input formats and documentation corrections are all welcome.

## Reporting a bug

Open an issue with:

- the command you ran and the full output (`--format json` helps)
- your Python version (`python --version`) and operating system
- for a wrong match: the component type, slug and installed version, the
  Wordfence vulnerability id, and what you expected
- for a version that was not detected: the first lines of the plugin main file,
  `style.css` or `readme.txt` (strip anything private)

Never paste your Wordfence API key. Replace private host names with
`example.com`.

## Development setup

You need Python 3.10 or newer.

```console
$ git clone https://github.com/saizul/wp-vuln-audit.git
$ cd wp-vuln-audit
$ python -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e ".[dev]"
```

Before every commit:

```console
$ ruff check .
$ ruff format --check .
$ pytest
```

All three must pass; CI runs them on Python 3.10 to 3.13.

## Guidelines

- **No runtime dependencies.** Standard library only. Development tools go in
  the `dev` extra.
- **Tests never touch the network.** Use `FakeTransport` from
  `tests/conftest.py` for the feed and remote scans, and `make_wp()` for fake
  WordPress trees.
- **Version comparison follows PHP.** A change to `versions.py` needs a test
  with the result PHP's `version_compare()` gives for the same input.
- **Fixture data stays fictional.** Use made-up plugin slugs, ids and CVE
  numbers in `tests/fixtures/` and `examples/`; do not copy records from the
  live feed.
- **Every change comes with a test** that fails without it.
- Add a line to the `Unreleased` section of `CHANGELOG.md` for anything a user
  would notice.

## Project layout

```text
src/wp_vuln_audit/
    versions.py    PHP version_compare() port, version clean-up
    ranges.py      affected_versions ranges and label parsing
    feed.py        feed records, parsing and lookup index
    cache.py       feed download, cache and conditional requests
    http.py        transport, gzip, rate limiter
    inventory.py   Component and Inventory
    wp_local.py    WordPress directory scanner
    wpcli.py       WP-CLI JSON and core version parsing
    remote.py      opt-in remote version detection
    ignore.py      the .wpvulnignore format
    audit.py       matching and filtering
    report/        text, JSON, Markdown and SARIF renderers
    cli.py         command-line interface
tests/             pytest suite and fixture feeds
examples/          sample site, sample feed, CI workflow, scripts
```

## Pull requests

Keep pull requests focused on one change, describe what it does and why, and
mention anything you could not test. By contributing you agree that your work
is released under the MIT license of this project.
