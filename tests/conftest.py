"""Shared fixtures for Phase 1 security tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api_security import reset_security_state  # noqa: E402
from backend_core import app as analysis_app  # noqa: E402
from threat_filter_core import app as threat_app  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_security_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("VERITAS_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    monkeypatch.delenv("API_RATE_LIMIT", raising=False)
    monkeypatch.delenv("API_RATE_WINDOW_SECONDS", raising=False)
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("VERITAS_ENV", raising=False)
    monkeypatch.delenv("ENABLE_API_DOCS", raising=False)
    monkeypatch.delenv("CORS_ALLOW_ORIGINS", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    reset_security_state()
    yield
    reset_security_state()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(analysis_app)


@pytest.fixture()
def threat_client() -> TestClient:
    return TestClient(threat_app)
