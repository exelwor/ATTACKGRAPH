"""Data importer: bytes/files/dicts -> raw data -> AuditData."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from attackgraph.models import AuditData
from attackgraph.normalization import AuditValidationError, normalize


def parse_json(text: str | bytes) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditValidationError(
            [f"invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"]
        ) from exc
    except UnicodeDecodeError as exc:
        raise AuditValidationError([f"file is not valid UTF-8: {exc.reason}"]) from exc


def import_audit(source: Mapping | str | bytes | os.PathLike) -> AuditData:
    """Accept a dict, a path to a JSON file, or raw JSON bytes."""
    if isinstance(source, Mapping):
        return normalize(dict(source))
    if isinstance(source, bytes):
        return normalize(parse_json(source))
    try:
        with open(source, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise AuditValidationError([f"cannot read {source!s}: {exc.strerror}"]) from exc
    return normalize(parse_json(data))
