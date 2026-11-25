"""Normalization engine: raw JSON-like data -> validated AuditData.

Real scanners disagree on vocabulary ("moderate" vs "medium", CVSS numbers vs
words). This module maps all of that onto the small fixed vocabulary in models.py
and reports *every* problem at once, with a path such as ``findings[2].severity``,
so a user can fix a whole file in one go.
"""

from __future__ import annotations

import re
from typing import Any

from attackgraph.models import (
    Asset,
    AuditData,
    Exposure,
    Finding,
    FindingKind,
    Level,
    Relation,
    RelationKind,
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_LEVEL_ALIASES = {
    "info": "low",
    "informational": "low",
    "minor": "low",
    "moderate": "medium",
    "med": "medium",
    "important": "high",
    "severe": "high",
    "crit": "critical",
}
_KIND_ALIASES = {
    "vuln": "vulnerability",
    "cve": "vulnerability",
    "misconfig": "misconfiguration",
    "config": "misconfiguration",
    "iam": "permission",
    "privilege": "permission",
    "permissions": "permission",
    "excessive_permission": "permission",
    "excessive_permissions": "permission",
    "control": "missing_control",
    "missing_protection": "missing_control",
}
_RELATION_ALIASES = {
    "network_access": "network",
    "reachable": "network",
    "connects": "network",
    "connectivity": "network",
    "trusts": "trust",
    "trust_relationship": "trust",
    "admin": "trust",
    "admin_access": "trust",
    "ssh_key": "trust",
    "sso": "trust",
    "credential": "credentials",
    "credential_reuse": "credentials",
    "stored_credentials": "credentials",
    "secret": "credentials",
}
_EXPOSURE_ALIASES = {
    "public": "internet",
    "external": "internet",
    "internet_facing": "internet",
    "internal_only": "internal",
    "private": "internal",
}
# When two relations connect the same pair, keep the one that is easiest to abuse.
_RELATION_PRIORITY = {RelationKind.CREDENTIALS: 3, RelationKind.TRUST: 2, RelationKind.NETWORK: 1}


class AuditValidationError(ValueError):
    """Raised with the full list of problems found in the input."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _text(item: dict, names: tuple[str, ...], path: str, errors: list[str], required=True):
    for name in names:
        value = item.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    if required:
        errors.append(f"{path}.{names[0]}: required")
    return None


def _level(value: Any, path: str, errors: list[str]) -> Level | None:
    if isinstance(value, bool):
        errors.append(f"{path}: unknown level {value!r}")
        return None
    number = None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            pass
    if number is not None:  # CVSS score
        if not 0 <= number <= 10:
            errors.append(f"{path}: CVSS score {value!r} is outside 0-10")
            return None
        if number < 4:
            return Level.LOW
        if number < 7:
            return Level.MEDIUM
        if number < 9:
            return Level.HIGH
        return Level.CRITICAL
    key = _key(value) if value is not None else ""
    key = _LEVEL_ALIASES.get(key, key)
    try:
        return Level(key)
    except ValueError:
        errors.append(
            f"{path}: unknown value {value!r} (expected low, medium, high, critical or a CVSS number)"
        )
        return None


def _enum(enum_cls, value: Any, aliases: dict, path: str, errors: list[str]):
    key = _key(value)
    key = aliases.get(key, key)
    try:
        return enum_cls(key)
    except ValueError:
        allowed = ", ".join(m.value for m in enum_cls)
        errors.append(f"{path}: unknown value {value!r} (expected one of: {allowed})")
        return None


def _tags(value: Any, path: str, errors: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        errors.append(f"{path}: must be a list of strings or a comma-separated string")
        return ()
    return tuple(dict.fromkeys(_key(t) for t in value if str(t).strip()))


def _list(raw: dict, name: str, errors: list[str], required: bool) -> list:
    value = raw.get(name)
    if value is None:
        if required:
            errors.append(f"{name}: required")
        return []
    if not isinstance(value, list):
        errors.append(f"{name}: must be a list")
        return []
    return value


def normalize(raw: Any) -> AuditData:
    if not isinstance(raw, dict):
        raise AuditValidationError(["top level: must be a JSON object"])
    errors: list[str] = []

    meta = raw.get("metadata")
    name = raw.get("name") or (meta.get("name") if isinstance(meta, dict) else None)
    name = str(name).strip() if name else "Untitled audit"

    seen: set[str] = set()

    def claim_id(value: str | None, path: str) -> None:
        if value is None:
            return
        if value in seen:
            errors.append(f"{path}.id: duplicate id {value!r} (ids must be unique across assets and findings)")
        seen.add(value)

    assets: list[Asset] = []
    for i, item in enumerate(_list(raw, "assets", errors, required=True)):
        path = f"assets[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{path}: must be an object")
            continue
        aid = _text(item, ("id",), path, errors)
        claim_id(aid, path)
        aname = _text(item, ("name",), path, errors, required=False) or aid
        crit = Level.MEDIUM
        if item.get("criticality") is not None:
            crit = _level(item["criticality"], f"{path}.criticality", errors) or Level.MEDIUM
        exposure = Exposure.INTERNAL
        if item.get("exposure") is not None:
            exposure = (
                _enum(Exposure, item["exposure"], _EXPOSURE_ALIASES, f"{path}.exposure", errors)
                or Exposure.INTERNAL
            )
        if aid:
            assets.append(
                Asset(
                    id=aid,
                    name=aname,
                    type=_key(item.get("type") or "host"),
                    criticality=crit,
                    exposure=exposure,
                    tags=_tags(item.get("tags"), f"{path}.tags", errors),
                )
            )
    if not assets and not any(e.startswith("assets") for e in errors):
        errors.append("assets: at least one asset is required")
    asset_ids = {a.id for a in assets}

    findings: list[Finding] = []
    for i, item in enumerate(_list(raw, "findings", errors, required=False)):
        path = f"findings[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{path}: must be an object")
            continue
        fid = _text(item, ("id",), path, errors)
        claim_id(fid, path)
        owner = _text(item, ("asset", "asset_id"), path, errors)
        if owner and owner not in asset_ids:
            errors.append(f"{path}.asset: unknown asset {owner!r}")
        title = _text(item, ("title", "name"), path, errors)
        kind_raw = item.get("kind", item.get("type"))
        kind = None
        if kind_raw is None:
            errors.append(f"{path}.kind: required")
        else:
            kind = _enum(FindingKind, kind_raw, _KIND_ALIASES, f"{path}.kind", errors)
        sev_raw = item.get("severity", item.get("cvss"))
        severity = None
        if sev_raw is None:
            errors.append(f"{path}.severity: required")
        else:
            severity = _level(sev_raw, f"{path}.severity", errors)
        cve = item.get("cve")
        if cve:
            cve = str(cve).strip().upper()
            if not _CVE_RE.match(cve):
                errors.append(f"{path}.cve: {cve!r} is not a valid CVE id (CVE-YYYY-NNNN)")
                cve = None
        if fid and owner in asset_ids and title and kind and severity:
            findings.append(
                Finding(
                    id=fid,
                    asset_id=owner,
                    kind=kind,
                    title=title,
                    severity=severity,
                    description=str(item.get("description") or "").strip(),
                    cve=cve or None,
                    remediation=(str(item["remediation"]).strip() if item.get("remediation") else None),
                    tags=_tags(item.get("tags"), f"{path}.tags", errors),
                )
            )

    relations: dict[tuple[str, str], Relation] = {}
    for i, item in enumerate(_list(raw, "relations", errors, required=False)):
        path = f"relations[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{path}: must be an object")
            continue
        src = _text(item, ("source", "from"), path, errors)
        dst = _text(item, ("target", "to"), path, errors)
        ok = True
        for label, value in (("source", src), ("target", dst)):
            if value and value not in asset_ids:
                errors.append(f"{path}.{label}: unknown asset {value!r}")
                ok = False
        if src and src == dst:
            errors.append(f"{path}: source and target are the same asset")
            ok = False
        kind_raw = item.get("kind", item.get("type", "network"))
        kind = _enum(RelationKind, kind_raw, _RELATION_ALIASES, f"{path}.kind", errors)
        if not (src and dst and kind and ok):
            continue
        description = str(item.get("description") or "").strip()
        pairs = [(src, dst)] + ([(dst, src)] if item.get("bidirectional") else [])
        for a, b in pairs:
            current = relations.get((a, b))
            if current is None or _RELATION_PRIORITY[kind] > _RELATION_PRIORITY[current.kind]:
                relations[(a, b)] = Relation(a, b, kind, description)

    if errors:
        raise AuditValidationError(errors)
    return AuditData(name, tuple(assets), tuple(findings), tuple(relations.values()))
