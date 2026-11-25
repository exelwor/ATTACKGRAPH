"""Risk analysis engine.

Idea: a finding alone says little. What matters is whether weaknesses can be
*chained* from something an attacker can reach (an internet-facing asset) to
something that hurts to lose (a critical asset).

Scoring is deliberately simple enough to check by hand:

  step probability   = 1 - product(1 - p) over the target asset's weaknesses
                       (p: low 0.2, medium 0.4, high 0.7, critical 0.9, max 0.95),
                       or a fixed 0.6 / 0.7 for trust / credential relations
  path likelihood    = product of its step probabilities
  path impact        = criticality of the last asset (low 2.5 ... critical 10)
  blind-spot factor  = 1 + 0.05 per missing control on the path (at most 4)
  path risk          = min(10, likelihood * impact * blind-spot factor)

Headline score = highest path risk. Exposure index = sum of all path risks; it
is used to rank fixes because it also rewards removing redundant routes.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice

import networkx as nx

from attackgraph.graph import (
    attack_surface,
    blind_spots,
    build_graph,
    compromise_probability,
    vectors,
)
from attackgraph.models import AuditData, Exposure, Level

MAX_HOPS = 6  # longest path, counted in assets
MAX_PATHS = 1000  # safety valve for very dense graphs
BLIND_SPOT_STEP = 0.05
BLIND_SPOT_CAP = 4


@dataclass(frozen=True)
class Step:
    asset_id: str
    via: str  # "entry", "network", "trust" or "credentials"
    probability: float
    finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class AttackPath:
    steps: tuple[Step, ...]
    likelihood: float
    impact: float
    blind_spot_ids: tuple[str, ...]
    risk: float

    @property
    def assets(self) -> tuple[str, ...]:
        return tuple(s.asset_id for s in self.steps)

    @property
    def signature(self) -> str:
        return ">".join(self.assets)


@dataclass(frozen=True)
class Recommendation:
    finding_id: str
    removed_signatures: tuple[str, ...]
    exposure_reduction: float
    score_after: float


def entry_assets(audit: AuditData):
    return [a for a in audit.assets if a.exposure is Exposure.INTERNET]


def target_assets(audit: AuditData):
    """Assets that are worth attacking: the highest criticality present, if at least 'high'."""
    top = max((a.criticality for a in audit.assets), key=lambda c: c.rank, default=None)
    if top is None or top.rank < Level.HIGH.rank:
        return []
    return [a for a in audit.assets if a.criticality is top]


def find_paths(audit: AuditData, fixed: Iterable[str] = ()) -> list[AttackPath]:
    graph = build_graph(audit, fixed)
    surface = attack_surface(graph)
    by_id = {a.id: a for a in audit.assets}
    paths: list[AttackPath] = []

    for entry in entry_assets(audit):
        entry_vectors = vectors(graph, entry.id)
        if not entry_vectors:
            continue
        first_step = Step(
            entry.id, "entry", compromise_probability(entry_vectors), tuple(f.id for f in entry_vectors)
        )
        for target in target_assets(audit):
            if target.id == entry.id:
                sequences = [[entry.id]]
            else:
                sequences = nx.all_simple_paths(surface, entry.id, target.id, cutoff=MAX_HOPS - 1)
            for sequence in islice(sequences, MAX_PATHS):
                steps = [first_step]
                for a, b in zip(sequence, sequence[1:]):
                    edge = surface[a][b]
                    steps.append(Step(b, edge["relation"], edge["probability"], edge["via"]))
                likelihood = math.prod(s.probability for s in steps)
                spots = tuple(f.id for asset_id in sequence for f in blind_spots(graph, asset_id))
                factor = 1 + BLIND_SPOT_STEP * min(len(spots), BLIND_SPOT_CAP)
                impact = by_id[sequence[-1]].criticality.impact
                paths.append(
                    AttackPath(
                        steps=tuple(steps),
                        likelihood=round(likelihood, 4),
                        impact=impact,
                        blind_spot_ids=spots,
                        risk=round(min(10.0, likelihood * impact * factor), 2),
                    )
                )
                if len(paths) >= MAX_PATHS:
                    break
    paths.sort(key=lambda p: (-p.risk, p.signature))
    return paths[:MAX_PATHS]


def peak_score(paths: list[AttackPath]) -> float:
    return max((p.risk for p in paths), default=0.0)


def exposure_index(paths: list[AttackPath]) -> float:
    return round(sum(p.risk for p in paths), 2)


def recommend(
    audit: AuditData, paths: list[AttackPath], fixed: Iterable[str] = (), limit: int = 15
) -> list[Recommendation]:
    """Try fixing each relevant finding on its own and measure what disappears."""
    if not paths:
        return []
    fixed = set(fixed)
    base = {p.signature for p in paths}
    base_exposure = exposure_index(paths)
    on_paths = {asset for p in paths for asset in p.assets}
    result: list[Recommendation] = []
    for finding in audit.findings:
        if finding.id in fixed or finding.asset_id not in on_paths:
            continue
        after = find_paths(audit, fixed | {finding.id})
        reduction = base_exposure - exposure_index(after)
        if reduction <= 1e-9:
            continue
        remaining = {p.signature for p in after}
        result.append(
            Recommendation(
                finding_id=finding.id,
                removed_signatures=tuple(sorted(base - remaining)),
                exposure_reduction=round(reduction, 2),
                score_after=peak_score(after),
            )
        )
    result.sort(key=lambda r: (-r.exposure_reduction, -len(r.removed_signatures), r.finding_id))
    return result[:limit]
