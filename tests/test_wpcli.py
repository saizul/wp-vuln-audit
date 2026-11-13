from __future__ import annotations

import json

import pytest

from wp_vuln_audit.wpcli import WpCliError, parse_combined, parse_core_version, parse_list

PLUGINS = [
    {"name": "example-forms", "status": "active", "update": "available", "version": "2.0.3", "update_version": "2.4.2"},
    {"name": "cache-helper", "status": "inactive", "update": "none", "version": "1.3.0", "update_version": ""},
    {"name": "object-cache.php", "status": "dropin", "update": "none", "version": "", "update_version": ""},
    {"name": "site-tools", "status": "must-use", "update": "none", "version": "2.0", "update_version": ""},
    {"name": "unknown", "status": "active", "update": "none", "version": "", "update_version": ""},
]


def test_parse_plugin_list() -> None:
    comps = parse_list(json.dumps(PLUGINS), "plugin", "plugins.json")
    assert [c.slug for c in comps] == ["example-forms", "cache-helper", "site-tools", "unknown"]
    first = comps[0]
    assert first.version == "2.0.3" and first.status == "active" and first.source == "wp-cli"
    assert first.notes == ("update available: 2.4.2",)
    assert first.location == "plugins.json"
    assert comps[-1].version is None and "no version reported" in comps[-1].notes


def test_parse_theme_list() -> None:
    themes = [{"name": "demo-theme", "status": "parent", "update": "none", "version": "1.2"}]
    (t,) = parse_list(json.dumps(themes), "theme")
    assert t.type == "theme" and t.version == "1.2"


def test_leading_noise_is_skipped() -> None:
    text = "PHP Warning: something in /var/www/wp-config.php\n" + json.dumps(PLUGINS[:1]) + "\n"
    assert len(parse_list(text, "plugin")) == 1


def test_numeric_versions_are_strings() -> None:
    (c,) = parse_list('[{"name": "x", "version": 2}]', "plugin")
    assert c.version == "2"


@pytest.mark.parametrize("text", ["", "   ", "Error: This does not seem to be a WordPress installation.", "[{"])
def test_errors(text: str) -> None:
    with pytest.raises(WpCliError):
        parse_list(text, "plugin")


def test_object_instead_of_list_is_an_error() -> None:
    with pytest.raises(WpCliError):
        parse_list('{"name": "x"}', "plugin")


def test_bad_type() -> None:
    with pytest.raises(ValueError):
        parse_list("[]", "core")


def test_non_dict_items_and_missing_names_skipped() -> None:
    assert parse_list('[1, "a", {"version": "1"}, {"slug": "via-slug", "version": "1.0"}]', "plugin")[0].slug == (
        "via-slug"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("6.6.2\n", "6.6.2"),
        ("WordPress version: 6.6.2\nDatabase revision: 57155\n", "6.6.2"),
        ("", None),
    ],
)
def test_core_version(text: str, expected: str | None) -> None:
    assert parse_core_version(text) == expected


def test_combined_document() -> None:
    doc = {"core": "6.4.2", "plugins": PLUGINS[:2], "themes": [{"name": "demo-theme", "version": "1.2"}]}
    inv = parse_combined(json.dumps(doc), "site.json")
    assert inv.core is not None and inv.core.version == "6.4.2" and inv.core.source == "wp-cli"
    assert inv.counts() == {"core": 1, "plugin": 2, "theme": 1}


def test_combined_core_object_and_bare_list() -> None:
    inv = parse_combined(json.dumps({"core": {"version": "6.5"}}))
    assert inv.core is not None and inv.core.version == "6.5"
    inv2 = parse_combined(json.dumps(PLUGINS[:1]))
    assert inv2.counts()["plugin"] == 1


def test_combined_rejects_bad_shapes() -> None:
    assert len(parse_combined("[1]")) == 0  # non-object items are skipped
    with pytest.raises(WpCliError):
        parse_combined('"6.4"')
    with pytest.raises(WpCliError):
        parse_combined('{"plugins": {"a": 1}}')
