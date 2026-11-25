"""Domain model.

Everything downstream (normalization, graph, risk, reports) works with these
immutable types, so an object can never be modified halfway through an analysis.
Plain dataclasses are used on purpose: the core has no dependencies besides
NetworkX and can be tested anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Level(str, Enum):
    """Used for both finding severity and asset criticality."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    @property
    def probability(self) -> float:
        """How likely a weakness of this severity is to be exploited successfully."""
        return {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 0.9}[self.value]

    @property
    def impact(self) -> float:
        """How bad it is to lose an asset of this criticality (0-10 scale)."""
        return {"low": 2.5, "medium": 5.0, "high": 7.5, "critical": 10.0}[self.value]


class FindingKind(str, Enum):
    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY = "vulnerability"
    PERMISSION = "permission"
    MISSING_CONTROL = "missing_control"


# Missing controls do not give an attacker a way in; they hide the attacker.
EXPLOIT_KINDS = frozenset(
    {FindingKind.MISCONFIGURATION, FindingKind.VULNERABILITY, FindingKind.PERMISSION}
)


class Exposure(str, Enum):
    INTERNET = "internet"
    INTERNAL = "internal"


class RelationKind(str, Enum):
    NETWORK = "network"  # source can reach target on the network
    TRUST = "trust"  # source is trusted by target (admin rights, SSH keys, SSO)
    CREDENTIALS = "credentials"  # source holds credentials that work on target


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    type: str = "host"
    criticality: Level = Level.MEDIUM
    exposure: Exposure = Exposure.INTERNAL
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    id: str
    asset_id: str
    kind: FindingKind
    title: str
    severity: Level
    description: str = ""
    cve: str | None = None
    remediation: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Relation:
    source: str
    target: str
    kind: RelationKind = RelationKind.NETWORK
    description: str = ""


@dataclass(frozen=True)
class AuditData:
    name: str
    assets: tuple[Asset, ...]
    findings: tuple[Finding, ...]
    relations: tuple[Relation, ...]
