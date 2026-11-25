"""Command line interface.

  attackgraph analyze audit.json -o report.html --md report.md --fail-on 7
  attackgraph validate audit.json
  attackgraph sample > audit.json
  attackgraph serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path

from attackgraph import __version__
from attackgraph.importer import import_audit
from attackgraph.normalization import AuditValidationError
from attackgraph.pipeline import analyze
from attackgraph.report import render_html, render_markdown


def _sample_text() -> str:
    return resources.files("attackgraph").joinpath("data/sample_audit.json").read_text(encoding="utf-8")


def _fail(errors: list[str]) -> int:
    print("Input is not valid:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attackgraph", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"attackgraph {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyze an audit file and write reports")
    run.add_argument("audit", help="path to the audit JSON file")
    run.add_argument("-o", "--html", help="write an interactive HTML report here")
    run.add_argument("--md", help="write a Markdown report here")
    run.add_argument("--json", dest="json_out", help="write the full analysis as JSON here")
    run.add_argument("--fix", default="", help="comma-separated finding ids to treat as already fixed")
    run.add_argument(
        "--fail-on", type=float, metavar="SCORE", help="exit with code 1 if the peak risk is >= SCORE"
    )

    check = sub.add_parser("validate", help="check an audit file without analyzing it")
    check.add_argument("audit")

    sub.add_parser("sample", help="print a sample audit file")

    serve = sub.add_parser("serve", help="start the web app")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", default="attackgraph.db", help="SQLite file for saved analyses")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "sample":
        sys.stdout.write(_sample_text())
        return 0

    if args.command == "serve":
        try:
            import uvicorn

            from attackgraph.api import create_app
        except ImportError:
            print('The web server needs extra packages: pip install "attackgraph[server]"', file=sys.stderr)
            return 2
        uvicorn.run(create_app(args.db), host=args.host, port=args.port)
        return 0

    try:
        audit = import_audit(args.audit)
        if args.command == "validate":
            print(
                f"OK: {len(audit.assets)} assets, {len(audit.findings)} findings, "
                f"{len(audit.relations)} relations."
            )
            return 0
        fixed = [f.strip() for f in args.fix.split(",") if f.strip()]
        result = analyze(audit, fixed)
    except AuditValidationError as exc:
        return _fail(exc.errors)

    s = result["summary"]
    print(
        f"{result['name']}: peak risk {s['score']:.1f}/10 ({s['rating']}), "
        f"{s['paths']} attack path(s), exposure index {s['exposure_index']}."
    )
    for note in result["notes"]:
        print(f"note: {note}")
    for rec in result["recommendations"][:3]:
        finding = next(f for f in result["findings"] if f["id"] == rec["finding"])
        print(f"fix first: {finding['id']} {finding['title']} (-{rec['exposure_reduction_pct']}% exposure)")

    if args.html:
        Path(args.html).write_text(render_html(result), encoding="utf-8")
        print(f"wrote {args.html}")
    if args.md:
        Path(args.md).write_text(render_markdown(result), encoding="utf-8")
        print(f"wrote {args.md}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")

    if args.fail_on is not None and s["score"] >= args.fail_on:
        print(f"FAIL: peak risk {s['score']:.1f} >= threshold {args.fail_on}", file=sys.stderr)
        return 1
    return 0
