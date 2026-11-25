"""Graph builder (NetworkX).

Two graphs are used:

* the *property graph* has an node for every asset and every finding. Findings
  point at the asset they affect; assets point at assets they can reach.
* the *attack surface* is an asset-only graph that keeps only the moves an
  attacker can really make, each labelled with a success probability.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

import networkx as nx

from attackgraph.models import (
    EXPLOIT_KINDS,
    AuditData,
    Finding,
    FindingKind,
    RelationKind,
)

# Moving over a trust or credential relation needs no new exploit.
DIRECT_PROBABILITY = {RelationKind.TRUST: 0.6, RelationKind.CREDENTIALS: 0.7}
MAX_COMPROMISE_PROBABILITY = 0.95


def build_graph(audit: AuditData, fixed: Iterable[str] = ()) -> nx.DiGraph:
    """Property graph. Findings listed in ``fixed`` are left out (what-if analysis)."""
    fixed = set(fixed)
    graph = nx.DiGraph()
    for asset in audit.assets:
        graph.add_node(asset.id, kind="asset", data=asset)
    for finding in audit.findings:
        if finding.id in fixed:
            continue
        graph.add_node(finding.id, kind="finding", data=finding)
        graph.add_edge(finding.id, finding.asset_id, kind="affects")
    for relation in audit.relations:
        graph.add_edge(relation.source, relation.target, kind="relation", data=relation)
    return graph


def _findings_of(graph: nx.DiGraph, asset_id: str) -> list[Finding]:
    return [
        graph.nodes[n]["data"]
        for n in graph.predecessors(asset_id)
        if graph.nodes[n]["kind"] == "finding"
    ]


def vectors(graph: nx.DiGraph, asset_id: str) -> list[Finding]:
    """Weaknesses an attacker can use to take over the asset."""
    return [f for f in _findings_of(graph, asset_id) if f.kind in EXPLOIT_KINDS]


def blind_spots(graph: nx.DiGraph, asset_id: str) -> list[Finding]:
    """Missing controls: things that would let a defender notice or stop the attacker."""
    return [f for f in _findings_of(graph, asset_id) if f.kind is FindingKind.MISSING_CONTROL]


def compromise_probability(findings: Iterable[Finding]) -> float:
    """P(at least one weakness works) = 1 - product(1 - p_i), capped below certainty."""
    miss = math.prod(1 - f.severity.probability for f in findings)
    return min(MAX_COMPROMISE_PROBABILITY, 1 - miss)


def attack_surface(graph: nx.DiGraph) -> nx.DiGraph:
    """Asset-only graph of moves an attacker can make."""
    surface = nx.DiGraph()
    surface.add_nodes_from(n for n, d in graph.nodes(data=True) if d["kind"] == "asset")
    for source, target, edge in graph.edges(data=True):
        if edge["kind"] != "relation":
            continue
        relation = edge["data"]
        if relation.kind is RelationKind.NETWORK:
            weaknesses = vectors(graph, target)
            if not weaknesses:  # reachable, but nothing to exploit there
                continue
            probability = compromise_probability(weaknesses)
            via = tuple(f.id for f in weaknesses)
        else:
            probability = DIRECT_PROBABILITY[relation.kind]
            via = ()
        surface.add_edge(
            source, target, probability=probability, via=via, relation=relation.kind.value
        )
    return surface
