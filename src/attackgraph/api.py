"""HTTP API (FastAPI). Thin on purpose: all logic lives in the engine modules."""

import json
import os

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from attackgraph import __version__
from attackgraph.importer import import_audit
from attackgraph.normalization import AuditValidationError
from attackgraph.pipeline import analyze
from attackgraph.report import render_html, render_markdown
from attackgraph.storage import Storage


def _sample() -> dict:
    from importlib import resources

    text = resources.files("attackgraph").joinpath("data/sample_audit.json").read_text(encoding="utf-8")
    return json.loads(text)


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="ATTACKGRAPH", version=__version__)
    storage = Storage(db_path or os.environ.get("ATTACKGRAPH_DB", "attackgraph.db"))

    def not_found() -> HTTPException:
        return HTTPException(status_code=404, detail="analysis not found")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return render_html(None)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/sample")
    def sample() -> dict:
        return _sample()

    @app.post("/api/analyze")
    def analyze_audit(
        payload: dict = Body(...),
        fix: list[str] = Query(default=[]),
    ) -> dict:
        try:
            result = analyze(import_audit(payload), fix)
        except AuditValidationError as exc:
            raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
        result["id"] = storage.save(result)
        return result

    @app.get("/api/analyses")
    def list_analyses() -> list:
        return storage.list()

    @app.get("/api/analyses/{analysis_id}")
    def get_analysis(analysis_id: str) -> dict:
        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        result["id"] = analysis_id
        return result

    @app.get("/api/analyses/{analysis_id}/report.html", response_class=HTMLResponse)
    def report_html(analysis_id: str) -> str:
        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        return render_html(result)

    @app.get("/api/analyses/{analysis_id}/report.md")
    def report_md(analysis_id: str):
        from fastapi.responses import PlainTextResponse

        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        return PlainTextResponse(render_markdown(result), media_type="text/markdown")

    @app.delete("/api/analyses/{analysis_id}", status_code=204)
    def delete_analysis(analysis_id: str) -> None:
        if not storage.delete(analysis_id):
            raise not_found()

    return app


# Run with: uvicorn attackgraph.api:create_app --factory
