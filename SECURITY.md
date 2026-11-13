# Security policy

## Supported versions

Security fixes are made for the latest released minor version.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/saizul/wp-vuln-audit/security/advisories/new)
for this repository and include a description, the input that triggers the
problem and the version you used.

You can expect an acknowledgement within a few days. Once a fix is released
the advisory is published with credit to the reporter, unless you prefer to
stay anonymous.

## Scope

wp-vuln-audit reads untrusted files (plugin and theme headers, WP-CLI output,
feed JSON) and, with `--url --allow-remote`, makes HTTP requests. Things that
count as vulnerabilities include:

- input that makes parsing take excessive time or memory beyond the size of
  the input (headers are read from the first 8 KiB, remote bodies are capped)
- the API key being sent anywhere other than the configured feed URL, or
  written to a report, log or cache file
- a remote scan requesting another host than the one given, sending anything
  other than `GET`, or exceeding `--max-requests`
- a corrupt or malicious download replacing a valid cached feed
- writing files other than the cache and the file named with `--output`
- a vulnerable version being reported as safe because of a matching bug

Missing or wrong vulnerability data in the Wordfence feed itself should be
reported to Wordfence, not here.
