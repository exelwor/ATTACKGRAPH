import json

import pytest

from attackgraph.cli import main
from attackgraph.importer import import_audit
from attackgraph.normalization import AuditValidationError, normalize
from attackgraph.pipeline import analyze
from attackgraph.report import render_html, render_markdown
from attackgraph.storage import Storage
from conftest import mini


def sample_result():
    from importlib import resources

    text = resources.files("attackgraph").joinpath("data/sample_audit.json").read_text(encoding="utf-8")
    return analyze(normalize(json.loads(text)))


def test_sample_audit_has_the_expected_story():
    r = sample_result()
    assert r["summary"]["paths"] == 7
    assert r["summary"]["entry_points"] == 2 and r["summary"]["targets"] == 3
    assert r["paths"][0]["id"] == "P1" and r["paths"][0]["risk"] == r["summary"]["score"]
    assert r["recommendations"][0]["finding"] == "F-01"
    assert json.loads(json.dumps(r)) == r  # fully JSON-serializable


def test_result_references_are_consistent():
    r = sample_result()
    asset_ids = {a["id"] for a in r["assets"]}
    finding_ids = {f["id"] for f in r["findings"]}
    path_ids = {p["id"] for p in r["paths"]}
    assert all(f["asset"] in asset_ids for f in r["findings"])
    assert all(set(p["assets"]) <= asset_ids for p in r["paths"])
    assert all(set(a["findings"]) <= finding_ids for a in r["assets"])
    assert all(set(rec["paths_removed"]) <= path_ids for rec in r["recommendations"])
    assert all(set(f["on_paths"]) <= path_ids for f in r["findings"])


def test_fixed_findings_disappear_and_score_drops():
    audit = normalize(mini())
    result = analyze(audit, fixed=["F1"])
    assert result["summary"]["paths"] == 0 and result["summary"]["score"] == 0
    assert "F1" not in {f["id"] for f in result["findings"]}
    assert result["notes"]  # explains why there is nothing


def test_unknown_fix_id_is_an_error():
    with pytest.raises(AuditValidationError):
        analyze(normalize(mini()), fixed=["nope"])


def test_markdown_report_lists_paths_and_fixes():
    md = render_markdown(sample_result())
    assert md.startswith("# Attack path report: Northwind Lab")
    assert "## What to fix first" in md and "F-01" in md
    assert "Internet > web-01 > app-01 > db-01" in md


def test_html_report_embeds_data_and_cannot_break_out_of_the_script_tag():
    raw = mini()
    raw["name"] = "</script><script>alert(1)</script>"
    html = render_html(analyze(normalize(raw)))
    assert "/*ATTACKGRAPH_DATA*/null" not in html
    assert "</script><script>alert(1)" not in html
    assert render_html(None).count("/*ATTACKGRAPH_DATA*/null") == 1


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_cli_analyze_writes_all_outputs(tmp_path):
    audit = write(tmp_path, "audit.json", mini())
    out = [str(tmp_path / n) for n in ("r.html", "r.md", "r.json")]
    code = main(["analyze", audit, "-o", out[0], "--md", out[1], "--json", out[2]])
    assert code == 0
    assert all((tmp_path / n).stat().st_size > 0 for n in ("r.html", "r.md", "r.json"))
    assert json.loads((tmp_path / "r.json").read_text())["summary"]["paths"] == 1


def test_cli_fail_on_threshold_is_a_ci_gate(tmp_path):
    audit = write(tmp_path, "audit.json", mini())
    assert main(["analyze", audit, "--fail-on", "9"]) == 0
    assert main(["analyze", audit, "--fail-on", "6"]) == 1
    assert main(["analyze", audit, "--fail-on", "6", "--fix", "F1"]) == 0


def test_cli_invalid_input_exits_with_2(tmp_path):
    bad = write(tmp_path, "bad.json", {"assets": [{"id": "a"}], "findings": [{"id": "x"}]})
    assert main(["validate", bad]) == 2
    assert main(["analyze", str(tmp_path / "missing.json")]) == 2


def test_cli_sample_is_valid_input(tmp_path):
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert main(["sample"]) == 0
    path = tmp_path / "sample.json"
    path.write_text(buffer.getvalue(), encoding="utf-8")
    assert main(["validate", str(path)]) == 0
    assert import_audit(path).name.startswith("Northwind")


def test_storage_roundtrip(tmp_path):
    store = Storage(tmp_path / "t.db")
    result = sample_result()
    first = store.save(result)
    second = store.save(result)
    assert store.get(first)["name"] == result["name"]
    assert [row["id"] for row in store.list()] == [second, first]
    assert store.delete(first) is True and store.delete(first) is False
    assert store.get(first) is None
