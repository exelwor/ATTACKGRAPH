
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from attackgraph.api import create_app  # noqa: E402
from conftest import mini  # noqa: E402


def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "api.db")))


def test_health_and_index(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/health").json()["status"] == "ok"
    assert "ATTACKGRAPH" in c.get("/").text


def test_analyze_saves_and_returns_the_result(tmp_path):
    c = client(tmp_path)
    response = c.post("/api/analyze", json=mini())
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["paths"] == 1 and body["id"]
    assert c.get(f"/api/analyses/{body['id']}").json()["name"] == "mini"
    assert c.get("/api/analyses").json()[0]["id"] == body["id"]
    assert "<svg" in c.get(f"/api/analyses/{body['id']}/report.html").text
    assert c.get(f"/api/analyses/{body['id']}/report.md").text.startswith("# Attack path report")
    assert c.delete(f"/api/analyses/{body['id']}").status_code == 204
    assert c.get(f"/api/analyses/{body['id']}").status_code == 404


def test_invalid_audit_returns_422_with_every_error(tmp_path):
    raw = mini()
    raw["findings"][0]["severity"] = "banana"
    raw["findings"][1]["asset"] = "ghost"
    response = client(tmp_path).post("/api/analyze", json=raw)
    assert response.status_code == 422
    assert len(response.json()["detail"]["errors"]) == 2


def test_fix_parameter_is_applied(tmp_path):
    response = client(tmp_path).post("/api/analyze?fix=F1", json=mini())
    assert response.json()["summary"]["paths"] == 0


def test_sample_endpoint_returns_valid_input(tmp_path):
    c = client(tmp_path)
    sample = c.get("/api/sample").json()
    assert c.post("/api/analyze", json=sample).status_code == 200
