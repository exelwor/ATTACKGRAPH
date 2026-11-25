import pytest

from attackgraph.importer import import_audit
from attackgraph.models import Exposure, FindingKind, Level, RelationKind
from attackgraph.normalization import AuditValidationError, normalize
from conftest import mini


def errors_of(raw):
    with pytest.raises(AuditValidationError) as info:
        normalize(raw)
    return info.value.errors


def test_valid_audit_is_normalized():
    audit = normalize(mini())
    assert [a.id for a in audit.assets] == ["web", "db"]
    assert audit.assets[0].exposure is Exposure.INTERNET
    assert audit.findings[0].severity is Level.HIGH
    assert audit.relations[0].kind is RelationKind.NETWORK


def test_aliases_are_understood():
    raw = mini()
    raw["findings"][0].update(kind="vuln", severity="Moderate")
    raw["findings"][1].update(kind="Missing-Control", severity="important")
    raw["assets"][0]["exposure"] = "public"
    audit = normalize(raw)
    assert audit.findings[0].kind is FindingKind.VULNERABILITY
    assert audit.findings[0].severity is Level.MEDIUM
    assert audit.findings[1].kind is FindingKind.MISSING_CONTROL
    assert audit.findings[1].severity is Level.HIGH
    assert audit.assets[0].exposure is Exposure.INTERNET


def test_cvss_numbers_are_mapped_to_levels():
    levels = []
    for score in (0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, "10"):
        raw = mini()
        raw["findings"][0]["severity"] = score
        levels.append(normalize(raw).findings[0].severity)
    assert levels == [
        Level.LOW, Level.LOW, Level.MEDIUM, Level.MEDIUM,
        Level.HIGH, Level.HIGH, Level.CRITICAL, Level.CRITICAL,
    ]


def test_all_problems_are_reported_together():
    raw = mini()
    raw["findings"][0]["severity"] = "banana"
    raw["findings"][1]["asset"] = "ghost"
    raw["relations"][0]["target"] = "nowhere"
    errors = errors_of(raw)
    assert any(e.startswith("findings[0].severity") for e in errors)
    assert any(e.startswith("findings[1].asset") for e in errors)
    assert any(e.startswith("relations[0].target") for e in errors)


def test_duplicate_ids_are_rejected_across_assets_and_findings():
    raw = mini()
    raw["findings"][0]["id"] = "web"
    assert any("duplicate id 'web'" in e for e in errors_of(raw))


def test_cvss_out_of_range_and_bad_cve():
    raw = mini()
    raw["findings"][0]["severity"] = 11
    raw["findings"][1]["cve"] = "CVE-12"
    errors = errors_of(raw)
    assert any("outside 0-10" in e for e in errors)
    assert any("not a valid CVE" in e for e in errors)


def test_cve_is_uppercased():
    raw = mini()
    raw["findings"][0]["cve"] = "cve-2021-44228"
    assert normalize(raw).findings[0].cve == "CVE-2021-44228"


def test_bidirectional_relation_creates_both_directions():
    raw = mini()
    raw["relations"][0]["bidirectional"] = True
    pairs = {(r.source, r.target) for r in normalize(raw).relations}
    assert pairs == {("web", "db"), ("db", "web")}


def test_duplicate_relation_keeps_the_easiest_to_abuse():
    raw = mini()
    raw["relations"].append({"source": "web", "target": "db", "kind": "credentials"})
    relations = normalize(raw).relations
    assert len(relations) == 1 and relations[0].kind is RelationKind.CREDENTIALS


def test_self_relation_is_rejected():
    raw = mini()
    raw["relations"][0]["target"] = "web"
    assert any("same asset" in e for e in errors_of(raw))


def test_top_level_must_be_an_object_with_assets():
    assert errors_of([]) == ["top level: must be a JSON object"]
    assert errors_of({}) == ["assets: required"]


def test_import_from_bytes_and_bad_json(tmp_path):
    assert import_audit(b'{"assets": [{"id": "a"}]}').assets[0].id == "a"
    with pytest.raises(AuditValidationError) as info:
        import_audit(b"{nope")
    assert info.value.errors[0].startswith("invalid JSON")
    with pytest.raises(AuditValidationError) as info:
        import_audit(tmp_path / "missing.json")
    assert "cannot read" in info.value.errors[0]
