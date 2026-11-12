"""CORS, optional API-key authentication, rate limiting, and health tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api_security import reset_security_state


BENIGN_CODE = {"language": "python", "source_code": "def add(a, b):\n    return a + b\n"}


def test_combined_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "veritas-inspector-analysis-core"


def test_standalone_threat_filter_health(threat_client: TestClient) -> None:
    response = threat_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "veritas-inspector-threat-filter"


def test_cors_allows_configured_localhost_origin(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "http://localhost:4173"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:4173"


def test_cors_preflight_for_inspect_code(client: TestClient) -> None:
    response = client.options(
        "/api/v1/inspect-code",
        headers={
            "Origin": "http://localhost:4173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key",
        },
    )
    assert response.status_code in {200, 204}
    assert response.headers.get("access-control-allow-origin") == "http://localhost:4173"
    allow_headers = (response.headers.get("access-control-allow-headers") or "").lower()
    assert "x-api-key" in allow_headers or allow_headers == "*"


def test_cors_does_not_reflect_unknown_origin(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "https://evil.example"


def test_auth_disabled_when_no_api_key(client: TestClient) -> None:
    response = client.post("/api/v1/inspect-code", json=BENIGN_CODE)
    assert response.status_code == 200, response.text
    assert response.json()["verification_status"] in {"SECURE", "REVIEW_REQUIRED", "MALICIOUS"}


def test_auth_rejects_missing_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "phase1-secret-key")
    response = client.post("/api/v1/inspect-code", json=BENIGN_CODE)
    assert response.status_code == 401
    assert "API key" in response.json()["detail"]
    assert "phase1-secret-key" not in response.text


def test_auth_rejects_wrong_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "phase1-secret-key")
    response = client.post(
        "/api/v1/inspect-code",
        json=BENIGN_CODE,
        headers={"X-API-Key": "wrong-key"},
    )
    assert response.status_code == 401
    assert "phase1-secret-key" not in response.text
    assert "wrong-key" not in response.json()["detail"]


def test_auth_accepts_matching_header(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "phase1-secret-key")
    response = client.post(
        "/api/v1/inspect-code",
        json=BENIGN_CODE,
        headers={"X-API-Key": "phase1-secret-key"},
    )
    assert response.status_code == 200, response.text
    assert "phase1-secret-key" not in response.text


def test_auth_accepts_bearer_token(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VERITAS_API_KEY", "bearer-secret")
    response = client.post(
        "/api/v1/filter-threat",
        json={"payload_type": "url", "url": "https://example.com/"},
        headers={"Authorization": "Bearer bearer-secret"},
    )
    assert response.status_code == 200, response.text
    assert "bearer-secret" not in response.text


def test_health_is_exempt_from_api_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "phase1-secret-key")
    response = client.get("/health")
    assert response.status_code == 200


def test_rate_limit_returns_429(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_RATE_LIMIT", "2")
    monkeypatch.setenv("API_RATE_WINDOW_SECONDS", "60")
    reset_security_state()
    first = client.get("/health")
    second = client.get("/health")
    third = client.get("/health")
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["detail"] == "rate limit exceeded"
    assert third.headers.get("retry-after") is not None


def test_rate_limit_disabled_when_zero(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_RATE_LIMIT", "0")
    reset_security_state()
    statuses = [client.get("/health").status_code for _ in range(5)]
    assert statuses == [200, 200, 200, 200, 200]
