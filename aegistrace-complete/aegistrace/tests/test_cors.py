import logging

import pytest
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from agent.main import create_app as agent_app
from audit.main import create_app as audit_app, initialize
from common.cors import BrowserAPI, allowed_origins
from reconstruction.main import create_app as reconstruction_app

ORIGIN = "https://frontend.example.com"


@pytest.mark.parametrize("path,method", [("/chat", "POST"), ("/demo/session", "POST"), ("/health", "GET")])
def test_agent_preflights(monkeypatch, path, method):
    monkeypatch.setenv("ALLOWED_ORIGINS", f" , {ORIGIN}/, ,")
    monkeypatch.setenv("DEMO_MODE", "true")
    with TestClient(agent_app(capture=lambda event: None)) as client:
        response = client.options(path, headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "content-type,authorization",
        })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-max-age"] == "600"
    assert "access-control-allow-credentials" not in response.headers


@pytest.mark.parametrize("path,method", [
    ("/health", "GET"), ("/config.js", "GET"), ("/api/config", "GET"),
    ("/api/sessions", "GET"), ("/api/session/case/entries", "GET"),
    ("/api/session/case/verify", "GET"), ("/api/session/case/graph", "GET"),
    ("/api/session/case/export", "GET"), ("/api/session/case/tamper", "POST"),
])
def test_reconstruction_preflights(monkeypatch, tmp_path, path, method):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    monkeypatch.setenv("DEMO_MODE", "true")
    with TestClient(reconstruction_app(tmp_path / "audit.db")) as client:
        response = client.options(path, headers={"Origin": ORIGIN, "Access-Control-Request-Method": method})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN


def test_disallowed_origin_and_method(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    with TestClient(agent_app(capture=lambda event: None)) as client:
        denied = client.options("/chat", headers={"Origin": "https://denied.example.com", "Access-Control-Request-Method": "POST"})
        method = client.options("/chat", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "DELETE"})
        simple = client.get("/health", headers={"Origin": "https://denied.example.com"})
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers
    assert "access-control-allow-origin" not in simple.headers
    assert method.status_code == 400


def test_error_responses_keep_cors(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    app = reconstruction_app(tmp_path / "missing.db")
    error_app = BrowserAPI()

    @error_app.get("/unexpected-error")
    def unexpected():
        raise RuntimeError("test failure")

    with TestClient(app) as client:
        response = client.get("/health", headers={"Origin": ORIGIN})
        assert response.status_code == 503
        assert response.headers["access-control-allow-origin"] == ORIGIN
    with TestClient(error_app, raise_server_exceptions=False) as client:
        response = client.get("/unexpected-error", headers={"Origin": ORIGIN})
        assert response.status_code == 500
        assert response.headers["access-control-allow-origin"] == ORIGIN
    with TestClient(agent_app(capture=lambda event: None)) as client:
        response = client.post("/chat", json={}, headers={"Origin": ORIGIN})
        assert response.status_code == 422
        assert response.headers["access-control-allow-origin"] == ORIGIN


def test_stream_response_keeps_cors(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    app = BrowserAPI()

    @app.get("/stream")
    def stream():
        return StreamingResponse(iter(["data: test\n\n"]), media_type="text/event-stream")

    with TestClient(app) as client:
        response = client.get("/stream", headers={"Origin": ORIGIN})
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.text == "data: test\n\n"


def test_explicit_wildcard_warns_and_never_allows_credentials(monkeypatch, caplog):
    monkeypatch.setenv("ALLOWED_ORIGINS", " * ")
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        with TestClient(agent_app(capture=lambda event: None)) as client:
            response = client.get("/health", headers={"Origin": ORIGIN})
    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers
    assert "ALLOWED_ORIGINS=*" in caplog.text


@pytest.mark.parametrize("value", ["*,https://example.com", "https://example.com/path", "https://user:password@example.com", "https://example.com?secret=x", "not-an-origin"])
def test_invalid_origin_configuration_is_rejected(monkeypatch, value):
    monkeypatch.setenv("ALLOWED_ORIGINS", value)
    with pytest.raises(ValueError, match="origins only"):
        allowed_origins()


def test_empty_origins_do_not_fall_back_to_wildcard(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", " , , ")
    assert allowed_origins() == []


def test_audit_does_not_gain_browser_routes_or_cors(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    monkeypatch.setenv("AUDIT_WRITE_TOKEN", "test-only")
    with TestClient(audit_app(tmp_path / "audit.db")) as client:
        response = client.options("/ingest", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
        assert response.status_code == 405
        assert "access-control-allow-origin" not in response.headers
        assert client.get("/health").status_code == 404


def test_config_js_only_exposes_api_base_and_health_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_API_BASE", "https://api.example.com/prefix/")
    monkeypatch.setenv("GROQ_API_KEY", "test-private-value")
    path = tmp_path / "audit.db"
    initialize(path)
    before = path.read_bytes()
    with TestClient(reconstruction_app(path)) as client:
        response = client.get("/config.js")
        assert response.text == 'window.AEGIS_API_BASE = "https://api.example.com/prefix";\n'
        assert "test-private-value" not in response.text
        assert client.get("/health").status_code == 200
    assert path.read_bytes() == before
