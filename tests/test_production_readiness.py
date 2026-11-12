"""Phase 2B production-readiness tests.  These do not deploy anything."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api_security import (
    PRODUCTION_CORS_ORIGINS,
    api_docs_enabled,
    configured_cors_origins,
    fastapi_docs_kwargs,
    install_api_protections,
    is_production,
)


ROOT = Path(__file__).resolve().parents[1]
PAGES_ORIGIN = "https://mohamdmamdoh83-coder.github.io"


def test_wildcard_cors_is_never_enabled(monkeypatch) -> None:
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "*")
    origins = configured_cors_origins()
    assert "*" not in origins
    assert origins


def test_production_cors_defaults_to_github_pages(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CORS_ALLOW_ORIGINS", raising=False)
    assert is_production() is True
    assert configured_cors_origins() == list(PRODUCTION_CORS_ORIGINS)
    assert PAGES_ORIGIN in configured_cors_origins()
    assert "http://localhost:4173" not in configured_cors_origins()


def test_development_cors_keeps_localhost(monkeypatch) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    origins = configured_cors_origins()
    assert "http://localhost:4173" in origins
    assert "*" not in origins


def test_production_cors_allows_pages_origin_on_fresh_app(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CORS_ALLOW_ORIGINS", raising=False)
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    install_api_protections(app)
    client = TestClient(app)
    allowed = client.get("/health", headers={"Origin": PAGES_ORIGIN})
    assert allowed.status_code == 200
    assert allowed.headers.get("access-control-allow-origin") == PAGES_ORIGIN
    blocked = client.get("/health", headers={"Origin": "https://evil.example"})
    assert blocked.headers.get("access-control-allow-origin") != "https://evil.example"


def test_api_docs_disabled_in_production(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("ENABLE_API_DOCS", raising=False)
    assert api_docs_enabled() is False
    kwargs = fastapi_docs_kwargs()
    assert kwargs["docs_url"] is None
    assert kwargs["redoc_url"] is None
    assert kwargs["openapi_url"] is None
    app = FastAPI(**kwargs)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    install_api_protections(app)
    client = TestClient(app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_api_docs_can_be_enabled_explicitly(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ENABLE_API_DOCS", "true")
    assert api_docs_enabled() is True
    assert fastapi_docs_kwargs() == {}


def test_access_log_omits_api_key(client: TestClient, monkeypatch, caplog) -> None:
    monkeypatch.setenv("API_KEY", "phase2b-secret-key")
    caplog.set_level(logging.INFO, logger="veritas.api")
    response = client.post(
        "/api/v1/inspect-code",
        json={"language": "python", "source_code": "def add(a, b):\n    return a + b\n"},
        headers={"X-API-Key": "phase2b-secret-key"},
    )
    assert response.status_code == 200
    combined = caplog.text
    assert "phase2b-secret-key" not in combined
    assert "X-API-Key" not in combined
    assert "def add" not in combined


def test_unhandled_error_body_has_no_traceback(monkeypatch) -> None:
    app = FastAPI()

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("sensitive internals")

    install_api_protections(app)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")
    assert response.status_code == 500
    assert response.json()["detail"] == "internal error"
    assert "sensitive internals" not in response.text
    assert "Traceback" not in response.text


def test_dockerfile_and_env_example_do_not_embed_secrets() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "API_KEY=" not in dockerfile
    assert "uvicorn backend_core:app" in dockerfile
    assert "CORS_ALLOW_ORIGINS=https://mohamdmamdoh83-coder.github.io" in env_example
    assert "changeme" not in env_example.lower()
    assert "sk-" not in env_example
