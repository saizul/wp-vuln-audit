from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import make_wp, plugin_header, theme_header, write
from wp_vuln_audit.wp_local import (
    WordPressNotFound,
    read_core_version,
    read_file_headers,
    scan_local,
)


def test_scan_fake_site(wp_site: Path) -> None:
    inv = scan_local(wp_site)
    assert inv.core is not None and inv.core.version == "6.4.2"
    assert inv.core.location == "wp-includes/version.php"
    plugins = {c.slug: c for c in inv.by_type("plugin")}
    assert set(plugins) == {"example-forms", "cache-helper", "safe-plugin", "demo-slider"}
    assert plugins["example-forms"].version == "2.0.3"
    assert plugins["example-forms"].location == "wp-content/plugins/example-forms/example-forms.php"
    themes = {c.slug: c.version for c in inv.by_type("theme")}
    assert themes == {"demo-theme": "1.2", "twentytwentyfour": "1.0"}
    assert inv.counts() == {"core": 1, "plugin": 4, "theme": 2}
    assert inv.warnings == []


def test_core_version_variants(tmp_path: Path) -> None:
    write(tmp_path / "wp-includes" / "version.php", '<?php\n$wp_version = "6.7-RC1";\n')
    assert read_core_version(tmp_path) == "6.7-RC1"
    write(tmp_path / "wp-includes" / "version.php", "<?php\n$wp_version='6.6.2' ;\n")
    assert read_core_version(tmp_path) == "6.6.2"
    write(tmp_path / "wp-includes" / "version.php", "<?php\n// no version here\n")
    assert read_core_version(tmp_path) is None
    assert read_core_version(tmp_path / "missing") is None


def test_header_parsing_like_get_file_data(tmp_path: Path) -> None:
    p = write(
        tmp_path / "x.php",
        "<?php\r\n/*\r\n * Plugin Name:   Fancy Plugin  \r\n  * version: 3.2.1 */\r\n# Text Domain: fancy ?>\r\n",
    )
    h = read_file_headers(p, ("Plugin Name", "Version", "Text Domain", "Author"))
    assert h == {"Plugin Name": "Fancy Plugin", "Version": "3.2.1", "Text Domain": "fancy"}


def test_header_on_php_open_tag_line(tmp_path: Path) -> None:
    p = write(tmp_path / "y.php", "<?php /* Plugin Name: Inline\nVersion: 1.0 */")
    assert read_file_headers(p, ("Plugin Name", "Version")) == {"Plugin Name": "Inline", "Version": "1.0"}


def test_headers_after_8k_are_ignored(tmp_path: Path) -> None:
    p = write(tmp_path / "late.php", "<?php\n" + "// filler\n" * 1000 + "/* Plugin Name: Late */\n")
    assert read_file_headers(p, ("Plugin Name",)) == {}


def test_plugin_main_file_detection(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    d = root / "wp-content" / "plugins" / "odd-name"
    write(d / "includes.php", "<?php // helper file\n")
    write(d / "loader.php", plugin_header("Odd Name", "0.9.1"))
    write(d / "readme.txt", "=== Odd ===\nStable tag: 0.9.1\n")
    # Files in subdirectories are never plugin main files.
    write(d / "sub" / "fake.php", plugin_header("Fake", "9.9"))
    inv = scan_local(root)
    comp = next(c for c in inv.components if c.slug == "odd-name")
    assert comp.version == "0.9.1"
    assert comp.location.endswith("odd-name/loader.php")
    assert comp.name == "Odd Name"


def test_directory_without_plugin_header_is_skipped(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    write(root / "wp-content" / "plugins" / "assets" / "index.php", "<?php // Silence is golden.\n")
    write(root / "wp-content" / "plugins" / "index.php", "<?php // Silence is golden.\n")
    assert scan_local(root).by_type("plugin") == []


def test_single_file_plugins_and_hello_dolly(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    write(root / "wp-content" / "plugins" / "hello.php", plugin_header("Hello Dolly", "1.7.2"))
    write(root / "wp-content" / "plugins" / "my-tweak.php", plugin_header("My Tweak", "1.0"))
    slugs = {c.slug: c.version for c in scan_local(root).by_type("plugin")}
    assert slugs == {"hello-dolly": "1.7.2", "my-tweak": "1.0"}


def test_mu_plugins(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    write(root / "wp-content" / "mu-plugins" / "site-tools.php", plugin_header("Site Tools", "2.0"))
    # Directories inside mu-plugins are not loaded by WordPress.
    write(root / "wp-content" / "mu-plugins" / "lib" / "lib.php", plugin_header("Lib", "1.0"))
    comps = scan_local(root).by_type("plugin")
    assert [(c.slug, c.status) for c in comps] == [("site-tools", "must-use")]
    assert "must-use plugin" in comps[0].notes
    assert scan_local(root, include_mu=False).by_type("plugin") == []


def test_missing_versions_produce_warnings(tmp_path: Path) -> None:
    root = make_wp(tmp_path, plugins={"no-version": None}, themes={"bare": None})
    inv = scan_local(root)
    assert {c.slug: c.version for c in inv.components if c.type != "core"} == {"no-version": None, "bare": None}
    assert any("no-version" in w for w in inv.warnings)
    assert any("bare" in w for w in inv.warnings)


def test_child_theme_note(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    write(root / "wp-content" / "themes" / "kid" / "style.css", theme_header("Kid", "1.0", template="demo-theme"))
    (theme,) = scan_local(root).by_type("theme")
    assert theme.notes == ("child theme of demo-theme",)


def test_hidden_and_headerless_themes_skipped(tmp_path: Path) -> None:
    root = make_wp(tmp_path)
    write(root / "wp-content" / "themes" / ".git" / "style.css", theme_header("Hidden", "1"))
    write(root / "wp-content" / "themes" / "nostyle" / "index.php", "<?php\n")
    write(root / "wp-content" / "themes" / "plaincss" / "style.css", "body{}\n")
    assert scan_local(root).by_type("theme") == []


def test_custom_content_dir(tmp_path: Path) -> None:
    root = make_wp(tmp_path / "wp", plugins={})
    content = tmp_path / "content"
    write(content / "plugins" / "elsewhere" / "elsewhere.php", plugin_header("Elsewhere", "1.1"))
    inv = scan_local(root, content_dir=content)
    assert [c.slug for c in inv.by_type("plugin")] == ["elsewhere"]


def test_only_wp_content(tmp_path: Path) -> None:
    root = make_wp(tmp_path, core=None, plugins={"a": "1.0"})
    inv = scan_local(root)
    assert inv.core is None
    assert any("version.php" in w for w in inv.warnings)
    assert len(inv.by_type("plugin")) == 1


def test_core_only(tmp_path: Path) -> None:
    write(tmp_path / "wp-includes" / "version.php", "<?php $wp_version = '6.0';")
    inv = scan_local(tmp_path)
    assert inv.core is not None
    assert any("wp-content" in w for w in inv.warnings)


def test_toggles(wp_site: Path) -> None:
    inv = scan_local(wp_site, include_core=False, include_themes=False)
    assert inv.core is None and inv.by_type("theme") == [] and inv.by_type("plugin")
    assert scan_local(wp_site, include_plugins=False).by_type("plugin") == []


def test_not_wordpress(tmp_path: Path) -> None:
    with pytest.raises(WordPressNotFound):
        scan_local(tmp_path)
    with pytest.raises(WordPressNotFound):
        scan_local(tmp_path / "nope")


def test_unreadable_header_file_returns_empty(tmp_path: Path) -> None:
    assert read_file_headers(tmp_path / "missing.php", ("Version",)) == {}
