import pytest

from attackgraph.graph import attack_surface, build_graph, compromise_probability, vectors
from attackgraph.normalization import normalize
from attackgraph.risk import exposure_index, find_paths, peak_score, recommend
from conftest import mini


def audit_of(raw):
    return normalize(raw)


def test_property_graph_links_findings_to_assets():
    graph = build_graph(audit_of(mini()))
    assert graph.has_edge("F1", "web") and graph["F1"]["web"]["kind"] == "affects"
    assert graph.has_edge("web", "db") and graph["web"]["db"]["kind"] == "relation"
    assert "F1" not in build_graph(audit_of(mini()), fixed=["F1"])


def test_compromise_probability_combines_independent_weaknesses():
    audit = audit_of(mini())
    f = audit.findings[0]  # high = 0.7
    assert compromise_probability([f]) == pytest.approx(0.7)
    assert compromise_probability([f, f]) == pytest.approx(1 - 0.3 * 0.3)
    critical = audit.findings[1]
    assert compromise_probability([critical, critical, critical]) == 0.95  # capped


def test_network_edge_needs_a_weakness_on_the_target():
    raw = mini()
    raw["findings"].pop()  # db has nothing to exploit now
    surface = attack_surface(build_graph(audit_of(raw)))
    assert not surface.has_edge("web", "db")


def test_trust_edge_needs_no_weakness():
    raw = mini()
    raw["findings"].pop()
    raw["relations"][0]["kind"] = "trust"
    surface = attack_surface(build_graph(audit_of(raw)))
    assert surface["web"]["db"]["probability"] == 0.6


def test_path_risk_matches_hand_calculation():
    # entry: high weakness 0.7; db: critical weakness 0.9; likelihood 0.63; impact 10.
    paths = find_paths(audit_of(mini()))
    assert len(paths) == 1
    assert paths[0].assets == ("web", "db")
    assert paths[0].likelihood == pytest.approx(0.63)
    assert paths[0].risk == pytest.approx(6.3, abs=0.01)


def test_missing_controls_raise_the_risk_by_five_percent_each():
    raw = mini()
    raw["findings"].append(
        {"id": "F3", "asset": "db", "kind": "missing_control", "severity": "high", "title": "No logging"}
    )
    path = find_paths(audit_of(raw))[0]
    assert path.blind_spot_ids == ("F3",)
    assert path.risk == pytest.approx(6.3 * 1.05, abs=0.01)


def test_no_entry_point_means_no_paths():
    raw = mini()
    raw["assets"][0]["exposure"] = "internal"
    assert find_paths(audit_of(raw)) == []


def test_internet_facing_critical_asset_is_a_one_step_path():
    raw = mini()
    raw["assets"][1]["exposure"] = "internet"
    signatures = {p.signature for p in find_paths(audit_of(raw))}
    assert "db" in signatures and "web>db" in signatures


def test_fixing_the_only_entry_weakness_removes_every_path():
    audit = audit_of(mini())
    assert find_paths(audit, fixed=["F1"]) == []


def test_loops_do_not_hang_the_search():
    raw = mini()
    raw["relations"][0]["bidirectional"] = True
    assert len(find_paths(audit_of(raw))) == 1


def test_recommendations_rank_by_exposure_removed():
    raw = mini()
    raw["findings"].append(
        {"id": "F3", "asset": "web", "kind": "misconfiguration", "severity": "low", "title": "Banner"}
    )
    audit = audit_of(raw)
    paths = find_paths(audit)
    recs = recommend(audit, paths)
    # F2 is db's only weakness, so fixing it cuts the path entirely (-6.84).
    # F1 only lowers the odds (0.76 -> 0.2, -5.04); F3 barely matters (-0.54).
    assert [r.finding_id for r in recs] == ["F2", "F1", "F3"]
    assert recs[0].removed_signatures == ("web>db",) and recs[1].removed_signatures == ()
    assert recs[0].exposure_reduction > recs[1].exposure_reduction > recs[2].exposure_reduction > 0
    assert all(r.score_after <= peak_score(paths) for r in recs)
    assert exposure_index(paths) == pytest.approx(paths[0].risk)
    assert recs[0].exposure_reduction == pytest.approx(exposure_index(paths), abs=0.01)


def test_target_fallback_requires_at_least_high_criticality():
    raw = mini()
    raw["assets"][1]["criticality"] = "medium"
    assert find_paths(audit_of(raw)) == []
    raw["assets"][1]["criticality"] = "high"
    assert len(find_paths(audit_of(raw))) == 1


def test_vectors_exclude_missing_controls():
    raw = mini()
    raw["findings"][1]["kind"] = "missing_control"
    graph = build_graph(audit_of(raw))
    assert vectors(graph, "db") == []
