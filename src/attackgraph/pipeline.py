"""Glue: AuditData -> one JSON-serializable analysis result.

The result is the single contract between the Python engine and every consumer
(web UI, HTML/Markdown reports, API, CI gate).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone

import networkx as nx

from attackgraph import __version__
from attackgraph.graph import build_graph
from attackgraph.models import AuditData, Level, RelationKind
from attackgraph.normalization import AuditValidationError
from attackgraph.remediation import suggest_action
from attackgraph.risk import (
    AttackPath,
    entry_assets,
    exposure_index,
    find_paths,
    peak_score,
    recommend,
    target_assets,
)

RATINGS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.01, "low"))


def rating(score: float) -> str:
    for threshold, label in RATINGS:
        if score >= threshold:
            return label
    return "none"


def _layers(audit: AuditData) -> dict[str, int]:
    """Column of each asset for drawing: hops from the nearest internet-facing asset."""
    graph = nx.DiGraph()
    graph.add_nodes_from(a.id for a in audit.assets)
    graph.add_edges_from((r.source, r.target) for r in audit.relations)
    sources = [a.id for a in entry_assets(audit)] or [n for n in graph if graph.in_degree(n) == 0]
    sources = sources or [a.id for a in audit.assets]
    dist = nx.multi_source_dijkstra_path_length(graph, sources)
    unreachable = max(dist.values(), default=0) + 1
    return {a.id: dist.get(a.id, unreachable) for a in audit.assets}


def _narrate(audit: AuditData, path: AttackPath) -> list[str]:
    assets = {a.id: a for a in audit.assets}
    findings = {f.id: f for f in audit.findings}
    relations = {(r.source, r.target): r for r in audit.relations}
    lines = []
    previous = None
    for step in path.steps:
        name = assets[step.asset_id].name
        used = "; ".join(findings[i].title for i in step.finding_ids)
        if step.via == "entry":
            lines.append(f"Break into {name} from the internet using: {used}.")
        elif step.via == "network":
            lines.append(f"Move from {assets[previous].name} to {name} over the network using: {used}.")
        else:
            note = relations[(previous, step.asset_id)].description
            how = "trust" if step.via == RelationKind.TRUST.value else "stored credentials"
            extra = f" ({note})" if note else ""
            lines.append(
                f"Move from {assets[previous].name} to {name} by abusing {how}{extra}."
            )
        previous = step.asset_id
    return lines


def analyze(audit: AuditData, fixed: Iterable[str] = ()) -> dict:
    fixed = tuple(dict.fromkeys(fixed))
    known = {f.id for f in audit.findings}
    unknown = [f for f in fixed if f not in known]
    if unknown:
        raise AuditValidationError([f"fix: unknown finding id {f!r}" for f in unknown])

    paths = find_paths(audit, fixed)
    recs = recommend(audit, paths, fixed)
    path_ids = {p.signature: f"P{i}" for i, p in enumerate(paths, 1)}
    graph = build_graph(audit, fixed)
    layers = _layers(audit)
    entries = {a.id for a in entry_assets(audit)}
    targets = {a.id for a in target_assets(audit)}
    findings = {f.id: f for f in audit.findings if f.id not in fixed}
    assets = {a.id: a for a in audit.assets}

    used_by: dict[str, list[str]] = {fid: [] for fid in findings}
    for path in paths:
        pid = path_ids[path.signature]
        touched = {fid for s in path.steps for fid in s.finding_ids} | set(path.blind_spot_ids)
        for fid in touched:
            used_by[fid].append(pid)

    asset_risk = {a: 0.0 for a in assets}
    for path in paths:
        for asset_id in path.assets:
            asset_risk[asset_id] = max(asset_risk[asset_id], path.risk)

    notes = []
    if not entries:
        notes.append("No asset has exposure 'internet', so no attack can start. Mark entry points.")
    if not targets:
        notes.append("No asset has criticality 'high' or 'critical', so there is nothing to protect.")
    if entries and targets and not paths:
        notes.append("No attack path connects an internet-facing asset to a critical asset.")

    score = peak_score(paths)
    severities = Counter(f.severity.value for f in findings.values())
    return {
        "schema": 1,
        "tool_version": __version__,
        "name": audit.name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fixed": list(fixed),
        "notes": notes,
        "summary": {
            "score": score,
            "rating": rating(score),
            "exposure_index": exposure_index(paths),
            "paths": len(paths),
            "assets": len(assets),
            "findings": len(findings),
            "entry_points": len(entries),
            "targets": len(targets),
            "by_severity": {lvl.value: severities.get(lvl.value, 0) for lvl in Level},
        },
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "type": a.type,
                "criticality": a.criticality.value,
                "exposure": a.exposure.value,
                "tags": list(a.tags),
                "layer": layers[a.id],
                "is_entry": a.id in entries,
                "is_target": a.id in targets,
                "risk": asset_risk[a.id],
                "findings": [f.id for f in audit.findings if f.asset_id == a.id and f.id in findings],
            }
            for a in audit.assets
        ],
        "findings": [
            {
                "id": f.id,
                "asset": f.asset_id,
                "kind": f.kind.value,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "cve": f.cve,
                "tags": list(f.tags),
                "action": suggest_action(f),
                "on_paths": used_by[f.id],
            }
            for f in findings.values()
        ],
        "relations": [
            {
                "source": r.source,
                "target": r.target,
                "kind": r.kind.value,
                "description": r.description,
                "on_paths": [
                    path_ids[p.signature]
                    for p in paths
                    if any(
                        (a, b) == (r.source, r.target)
                        for a, b in zip(p.assets, p.assets[1:])
                    )
                ],
            }
            for r in audit.relations
        ],
        "paths": [
            {
                "id": path_ids[p.signature],
                "assets": list(p.assets),
                "risk": p.risk,
                "rating": rating(p.risk),
                "likelihood": p.likelihood,
                "impact": p.impact,
                "blind_spots": list(p.blind_spot_ids),
                "summary": " > ".join(["Internet"] + [assets[a].name for a in p.assets]),
                "steps": [
                    {
                        "asset": s.asset_id,
                        "via": s.via,
                        "probability": round(s.probability, 4),
                        "findings": list(s.finding_ids),
                        "text": text,
                    }
                    for s, text in zip(p.steps, _narrate(audit, p))
                ],
            }
            for p in paths
        ],
        "recommendations": [
            {
                "finding": r.finding_id,
                "paths_removed": [path_ids[s] for s in r.removed_signatures],
                "exposure_reduction": r.exposure_reduction,
                "exposure_reduction_pct": round(
                    100 * r.exposure_reduction / exposure_index(paths), 1
                ),
                "score_after": r.score_after,
            }
            for r in recs
        ],
    }
