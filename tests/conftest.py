import copy

SAMPLE_MINI = {
    "name": "mini",
    "assets": [
        {"id": "web", "name": "web", "criticality": "medium", "exposure": "internet"},
        {"id": "db", "name": "db", "criticality": "critical"},
    ],
    "findings": [
        {"id": "F1", "asset": "web", "kind": "vulnerability", "severity": "high", "title": "RCE"},
        {"id": "F2", "asset": "db", "kind": "misconfiguration", "severity": "critical", "title": "Open admin"},
    ],
    "relations": [{"source": "web", "target": "db", "kind": "network"}],
}


def mini():
    """A fresh copy of the smallest audit that contains one attack path."""
    return copy.deepcopy(SAMPLE_MINI)
