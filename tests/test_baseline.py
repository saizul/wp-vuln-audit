from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from tests.conftest import PRODUCTION_FEED, make_wp, vid
from wp_vuln_audit import AuditOptions, Baseline, BaselineError, audit, compare, scan_local
from wp_vuln_audit.cli import main
from wp_vuln_audit.ignore import IgnoreList
from wp_vuln_audit.report import render, render_json, render_sarif

FEED = str(PRODUCTION_FEED)
ALL = {vid(1), vid(3), vid(4), vid(5), vid(6), vid(7)}


def run(argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(""), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    monkeypatch.setenv("WP_VULN_AUDIT_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("NO_COLOR", "1")


def _result(feed, site: Path, **opts):
    return audit(feed, scan_local(site), AuditOptions(**opts))


def _report_without(feed, site: Path, *drop: str) -> dict:
    data = json.loads(render_json(_result(feed, site)))
    data["findings"] = [f for f in data["findings"] if f["id"] not in drop]
    return data


def _write(path: Path, data: dict) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# ------------------------------------------------------------------ loading


def test_load_json_report(feed, wp_site: Path) -> None:
    baseline = Baseline.from_text(render_json(_result(feed, wp_site)), "b.json")
    assert len(baseline) == 6
    assert baseline.format == "json"
    assert ("core", "wordpress", vid(1)) in baseline
    assert ("plugin", "example-forms", vid(3)) in baseline
    entry = next(e for e in baseline.entries if e.id == vid(3))
    assert entry.version == "2.0.3" and entry.title and entry.severity


def test_load_sarif_report(feed, wp_site: Path) -> None:
    baseline = Baseline.from_text(render_sarif(_result(feed, wp_site)))
    assert baseline.format == "sarif"
    assert {e.id for e in baseline.entries} == ALL
    assert all(e.severity for e in baseline.entries)


def test_sarif_absent_results_are_skipped(feed, wp_site: Path) -> None:
    doc = json.loads(render_sarif(_result(feed, wp_site)))
    doc["runs"][0]["results"][0]["baselineState"] = "absent"
    assert len(Baseline.from_report(doc)) == 5


def test_ignored_findings_are_part_of_the_baseline(feed, wp_site: Path) -> None:
    ignore = IgnoreList.parse(f"{vid(1)}\n")
    baseline = Baseline.from_text(render_json(_result(feed, wp_site, ignore=ignore)))
    assert ("core", "wordpress", vid(1)) in baseline
    assert len(baseline) == 6


def test_duplicate_entries_collapse() -> None:
    item = {"id": vid(1), "component": {"type": "plugin", "slug": "Example-Forms", "version": "1.0"}}
    data = {"tool": {"name": "wp-vuln-audit"}, "findings": [item, item], "ignored": [item]}
    baseline = Baseline.from_report(data)
    assert len(baseline) == 1
    assert ("plugin", "example-forms", vid(1)) in baseline


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"findings": []},
        {"tool": {"name": "other-tool"}, "findings": []},
        {"tool": {"name": "wp-vuln-audit"}, "findings": {}},
        {"tool": {"name": "wp-vuln-audit"}, "findings": [{"id": vid(1)}]},
        {"tool": {"name": "wp-vuln-audit"}, "findings": [{"id": "", "component": {"type": "plugin", "slug": "x"}}]},
        {"tool": {"name": "wp-vuln-audit"}, "findings": [{"id": vid(1), "component": {"type": "mu", "slug": "x"}}]},
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "another-scanner"}}, "results": []}]},
        {"version": "2.1.0", "runs": {}},
    ],
)
def test_invalid_reports(data) -> None:
    with pytest.raises(BaselineError):
        Baseline.from_report(data)


def test_invalid_json_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="invalid JSON"):
        Baseline.from_text("{nope")
    with pytest.raises(BaselineError, match="cannot read"):
        Baseline.load(tmp_path / "missing.json")


# ------------------------------------------------------------------ comparing


def test_compare_splits_new_unchanged_and_resolved(feed, wp_site: Path) -> None:
    data = _report_without(feed, wp_site, vid(1), vid(4))
    data["findings"].append(
        {"id": vid(99), "title": "Old issue", "severity": "high", "component": {"type": "plugin", "slug": "gone"}}
    )
    baseline = Baseline.from_report(data)
    result = _result(feed, wp_site)
    cmp = compare(result, baseline)
    assert result.baseline is cmp
    assert {f.vulnerability.id for f in cmp.new} == {vid(1), vid(4)}
    assert {f.vulnerability.id for f in cmp.unchanged} == ALL - {vid(1), vid(4)}
    assert [e.id for e in cmp.resolved] == [vid(99)]
    assert all(cmp.state(f) == "new" for f in cmp.new)
    assert all(cmp.state(f) == "unchanged" for f in cmp.unchanged)


def test_version_change_keeps_finding_unchanged(feed, tmp_path: Path) -> None:
    old = make_wp(tmp_path / "old", core=None, plugins={"example-forms": "2.0.3"})
    new = make_wp(tmp_path / "new", core=None, plugins={"example-forms": "2.1.0"})
    baseline = Baseline.from_text(render_json(_result(feed, old)))
    result = _result(feed, new)
    assert [f.vulnerability.id for f in result.findings] == [vid(3)]
    cmp = compare(result, baseline)
    # vid(3) still affects 2.1.0 and stays unchanged; vid(4) was fixed by the update.
    assert cmp.new == []
    assert [f.vulnerability.id for f in cmp.unchanged] == [vid(3)]
    assert [e.id for e in cmp.resolved] == [vid(4)]


def test_now_ignored_finding_is_not_resolved(feed, wp_site: Path) -> None:
    baseline = Baseline.from_text(render_json(_result(feed, wp_site)))
    result = _result(feed, wp_site, ignore=IgnoreList.parse(f"{vid(1)}\n"))
    cmp = compare(result, baseline)
    assert cmp.new == [] and cmp.resolved == []


def test_fails_new_only(feed, wp_site: Path) -> None:
    baseline = Baseline.from_text(render_json(_result(feed, wp_site)))
    result = _result(feed, wp_site)
    compare(result, baseline)
    assert result.fails("any")
    assert not result.fails("any", new_only=True)
    assert not result.fails("low", new_only=True)


def test_reports_show_baseline_state(feed, wp_site: Path) -> None:
    baseline = Baseline.from_report(_report_without(feed, wp_site, vid(1)))
    result = _result(feed, wp_site)
    compare(result, baseline)
    data = json.loads(render(result, "json"))
    states = {f["id"]: f["baseline_state"] for f in data["findings"]}
    assert states[vid(1)] == "new"
    assert {s for k, s in states.items() if k != vid(1)} == {"unchanged"}
    assert data["summary"]["new"] == 1 and data["summary"]["resolved"] == 0
    assert data["baseline"]["unchanged"] == 5
    sarif = json.loads(render(result, "sarif"))
    sarif_states = {r["ruleId"]: r["baselineState"] for r in sarif["runs"][0]["results"]}
    assert sarif_states == states
    text = render(result, "text")
    assert text.count("[new]") == 1
    assert "1 new, 5 unchanged, 0 resolved since the baseline" in text
    md = render(result, "markdown")
    assert md.count("**New:**") == 1
    assert "**1** new, 5 unchanged, 0 resolved" in md


def test_reports_without_baseline_are_unchanged(feed, wp_site: Path) -> None:
    result = _result(feed, wp_site)
    data = json.loads(render(result, "json"))
    assert "baseline" not in data and "new" not in data["summary"]
    assert all("baseline_state" not in f for f in data["findings"])
    assert all("baselineState" not in r for r in json.loads(render(result, "sarif"))["runs"][0]["results"])
    assert "[new]" not in render(result, "text")


def test_resolved_listed_in_text_and_markdown(feed, wp_site: Path, tmp_path: Path) -> None:
    data = json.loads(render_json(_result(feed, wp_site)))
    data["findings"].append(
        {
            "id": vid(98),
            "title": "Removed plugin XSS",
            "component": {"type": "plugin", "slug": "removed", "version": "1.0"},
        }
    )
    result = _result(feed, wp_site)
    compare(result, Baseline.from_report(data))
    assert "Resolved since the baseline:" in render(result, "text")
    assert "plugin removed 1.0: Removed plugin XSS" in render(result, "text")
    assert "Resolved since the baseline</summary>" in render(result, "markdown")


# ------------------------------------------------------------------ CLI


def test_cli_baseline_only_new_findings_fail(wp_site: Path, tmp_path: Path) -> None:
    base = tmp_path / "baseline.json"
    code, _, _ = run(["scan", str(wp_site), "--feed-file", FEED, "-f", "json", "-o", str(base)])
    assert code == 1
    code, out, err = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(base)])
    assert code == 0, err
    assert "0 new, 6 unchanged, 0 resolved since the baseline" in out
    assert "baseline: 0 new, 6 unchanged, 0 resolved" in err
    code, _, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(base), "--fail-scope", "all"])
    assert code == 1


def test_cli_new_finding_fails(wp_site: Path, tmp_path: Path) -> None:
    from wp_vuln_audit.feed import Feed

    data = _report_without(Feed.from_file(FEED), wp_site, vid(3))
    base = _write(tmp_path / "b.json", data)
    code, out, err = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", base, "--new-only", "-f", "json"])
    assert code == 1, err
    report = json.loads(out)
    assert [f["id"] for f in report["findings"]] == [vid(3)]
    assert report["baseline"]["new"] == 1 and report["baseline"]["unchanged"] == 5


def test_cli_sarif_baseline(wp_site: Path, tmp_path: Path) -> None:
    base = tmp_path / "prev.sarif"
    run(["scan", str(wp_site), "--feed-file", FEED, "-f", "sarif", "-o", str(base)])
    code, out, _ = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(base), "-f", "sarif"])
    assert code == 0
    assert {r["baselineState"] for r in json.loads(out)["runs"][0]["results"]} == {"unchanged"}


def test_cli_write_baseline_bootstrap(wp_site: Path, tmp_path: Path) -> None:
    base = tmp_path / "state" / "baseline.json"
    base.parent.mkdir()
    argv = ["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(base), "--write-baseline", str(base)]
    code, _, err = run(argv)
    assert code == 1
    assert "does not exist yet" in err and "wrote baseline" in err
    assert {f["id"] for f in json.loads(base.read_text())["findings"]} == ALL
    code, _, err = run(argv)
    assert code == 0, err


def test_cli_write_baseline_keeps_all_findings_with_new_only(wp_site: Path, tmp_path: Path) -> None:
    base = tmp_path / "b.json"
    nxt = tmp_path / "next.json"
    run(["scan", str(wp_site), "--feed-file", FEED, "--write-baseline", str(base), "-f", "json"])
    code, out, _ = run(
        ["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(base), "--new-only", "--write-baseline", str(nxt)]
    )
    assert code == 0
    assert "No known vulnerabilities found." in out
    assert len(json.loads(nxt.read_text())["findings"]) == 6


def test_cli_baseline_errors(wp_site: Path, tmp_path: Path) -> None:
    code, _, err = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(tmp_path / "missing.json")])
    assert code == 2 and "cannot read" in err
    bad = tmp_path / "bad.json"
    bad.write_text('{"something": "else"}')
    code, _, err = run(["scan", str(wp_site), "--feed-file", FEED, "--baseline", str(bad)])
    assert code == 2 and "not a wp-vuln-audit" in err
    code, _, err = run(["scan", str(wp_site), "--feed-file", FEED, "--new-only"])
    assert code == 2 and "--new-only needs --baseline" in err


def test_cli_check_with_baseline(tmp_path: Path) -> None:
    base = tmp_path / "b.json"
    run(["check", "plugin", "example-forms", "2.0.3", "--feed-file", FEED, "-f", "json", "-o", str(base)])
    code, _, _ = run(["check", "plugin", "example-forms", "2.0.3", "--feed-file", FEED, "--baseline", str(base)])
    assert code == 0
