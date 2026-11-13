#!/bin/sh
# Nightly check on a server with WP-CLI. Mails the Markdown report when something is found.
# Usage: WORDFENCE_API_KEY=... ./server-cron.sh /var/www/example.com admin@example.com
set -eu

SITE="$1"
MAILTO="$2"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

wp --path="$SITE" plugin list --format=json > "$TMP/plugins.json"
wp --path="$SITE" theme list --format=json > "$TMP/themes.json"
wp --path="$SITE" core version > "$TMP/core.txt"

if ! wp-vuln-audit scan \
    --plugins-json "$TMP/plugins.json" \
    --themes-json "$TMP/themes.json" \
    --core-version "$TMP/core.txt" \
    --min-severity medium \
    --format markdown --output "$TMP/report.md"; then
  mail -s "Vulnerable WordPress components on $(hostname)" "$MAILTO" < "$TMP/report.md"
fi
