"""Report generator: Markdown for humans and CI logs, HTML for sharing."""

from __future__ import annotations

import json
from importlib import resources

_TOKEN = "/*ATTACKGRAPH_DATA*/null"


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(result: dict) -> str:
    s = result["summary"]
    findings = {f["id"]: f for f in result["findings"]}
    assets = {a["id"]: a for a in result["assets"]}
    out = [
        f"# Attack path report: {result['name']}",
        "",
        f"Generated {result['generated_at']} by ATTACKGRAPH {result['tool_version']}.",
        "",
        f"**Peak path risk: {s['score']:.1f} / 10 ({s['rating']})**. "
        f"{s['paths']} attack path(s) from {s['entry_points']} entry point(s) "
        f"to {s['targets']} critical target(s). Exposure index: {s['exposure_index']}.",
        "",
    ]
    if result["fixed"]:
        out += [f"Assumes these findings are already fixed: {', '.join(result['fixed'])}.", ""]
    out += [f"> {note}" for note in result["notes"]] + ([""] if result["notes"] else [])

    out += ["## Attack paths", ""]
    if not result["paths"]:
        out += ["None found.", ""]
    for path in result["paths"][:10]:
        out += [
            f"### {path['id']}: {path['summary']}",
            "",
            f"Risk {path['risk']:.1f} ({path['rating']}). "
            f"Likelihood {path['likelihood']:.0%}, impact {path['impact']:.1f}/10.",
            "",
        ]
        out += [f"{i}. {step['text']}" for i, step in enumerate(path["steps"], 1)]
        if path["blind_spots"]:
            missing = ", ".join(findings[f]["title"] for f in path["blind_spots"] if f in findings)
            out += ["", f"Detection gaps along this path: {missing}."]
        out.append("")
    if len(result["paths"]) > 10:
        out += [f"_{len(result['paths']) - 10} lower-risk path(s) omitted._", ""]

    out += ["## What to fix first", ""]
    if not result["recommendations"]:
        out += ["Nothing to fix: no attack path remains.", ""]
    else:
        out += [
            "| # | Finding | Asset | Paths removed | Exposure reduced | Peak score after | Action |",
            "|---|---------|-------|---------------|------------------|------------------|--------|",
        ]
        for i, rec in enumerate(result["recommendations"], 1):
            f = findings[rec["finding"]]
            out.append(
                f"| {i} | {_cell(f['id'] + ' ' + f['title'])} | {_cell(assets[f['asset']]['name'])} "
                f"| {len(rec['paths_removed'])} | {rec['exposure_reduction_pct']}% "
                f"| {rec['score_after']:.1f} | {_cell(f['action'])} |"
            )
        out.append("")

    out += [
        "## All findings",
        "",
        "| Id | Severity | Asset | Kind | Title | On paths |",
        "|----|----------|-------|------|-------|----------|",
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(result["findings"], key=lambda f: (order[f["severity"]], f["id"])):
        out.append(
            f"| {f['id']} | {f['severity']} | {_cell(assets[f['asset']]['name'])} | {f['kind']} "
            f"| {_cell(f['title'])} | {', '.join(f['on_paths']) or '-'} |"
        )
    return "\n".join(out) + "\n"


def viewer_template() -> str:
    return resources.files("attackgraph").joinpath("web/viewer.html").read_text(encoding="utf-8")


def render_html(result: dict | None) -> str:
    """Self-contained interactive report. ``None`` gives the empty app shell used by the server."""
    template = viewer_template()
    if result is None:
        return template
    payload = (
        json.dumps(result)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return template.replace(_TOKEN, payload)
