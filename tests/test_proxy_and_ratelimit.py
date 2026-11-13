"""P1 hardening tests: reverse-proxy trust, rate limiting, security headers."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api_security
from api_security import (
    _client_key,
    configured_trusted_proxies,
    fastapi_docs_kwargs,
    install_api_protections,
)


# ---------------------------------------------------------------------------
# Reverse-proxy trust (X-Forwarded-For spoofing resistance)
# ---------------------------------------------------------------------------


def test_forwarded_for_ignored_from_untrusted_peer(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    scope = {"type": "http", "client": ("203.0.113.5", 41234)}
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert _client_key(scope, headers) == "203.0.113.5"


def test_forwarded_for_honored_from_trusted_loopback_peer(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    scope = {"type": "http", "client": ("127.0.0.1", 41234)}
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert _client_key(scope, headers) == "1.2.3.4"


def test_trusted_proxy_cidr_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.0/8,2001:db8::1")
    scope = {"type": "http", "client": ("10.1.2.3", 41234)}
    headers = {"x-forwarded-for": "9.9.9.9"}
    assert _client_key(scope, headers) == "9.9.9.9"
    other = {"type": "http", "client": ("192.0.2.10", 1)}
    assert _client_key(other, headers) == "192.0.2.10"


def test_forwarded_for_ignored_when_proxy_trust_disabled(monkeypatch) -> None:
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    scope = {"type": "http", "client": ("127.0.0.1", 41234)}
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert _client_key(scope, headers) == "127.0.0.1"


def test_default_trusted_proxies_are_loopback_only() -> None:
    assert configured_trusted_proxies() == ["127.0.0.1", "::1"]


def test_spoofed_forwarded_for_cannot_evade_rate_limit(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("API_RATE_LIMIT", "2")
    for index in range(2):
        response = client.get("/health", headers={"X-Forwarded-For": f"10.0.0.{index}"})
        assert response.status_code == 200
    blocked = client.get("/health", headers={"X-Forwarded-For": "10.0.0.99"})
    assert blocked.status_code == 429


# ---------------------------------------------------------------------------
# Rate limiting: optional Redis backend with safe in-memory fallback
# ---------------------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.expire_calls = 0

    def incr(self, key: str) -> int:
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    def expire(self, key: str, seconds: int) -> bool:
        self.expire_calls += 1
        return True


class BrokenRedis:
    def incr(self, key: str) -> int:
        raise ConnectionError("redis down")

    def expire(self, key: str, seconds: int) -> bool:
        raise ConnectionError("redis down")


def test_rate_limit_uses_redis_when_available(monkeypatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(api_security, "_get_redis_client", lambda: fake)
    assert api_security._allow_rate("client-a", 2, 60) == (True, 1)
    assert api_security._allow_rate("client-a", 2, 60) == (True, 0)
    assert api_security._allow_rate("client-a", 2, 60) == (False, 0)
    assert fake.expire_calls == 1
    # Independent clients keep their own budgets.
    assert api_security._allow_rate("client-b", 2, 60) == (True, 1)


def test_rate_limit_falls_back_to_memory_on_redis_error(monkeypatch) -> None:
    monkeypatch.setattr(api_security, "_get_redis_client", lambda: BrokenRedis())
    assert api_security._allow_rate("client-a", 2, 60) == (True, 1)
    assert api_security._allow_rate("client-a", 2, 60) == (True, 0)
    assert api_security._allow_rate("client-a", 2, 60) == (False, 0)


def test_rate_limit_without_redis_url_uses_memory(monkeypatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert api_security._get_redis_client() is None
    assert api_security._allow_rate("client-a", 1, 60) == (True, 0)
    assert api_security._allow_rate("client-a", 1, 60) == (False, 0)


def test_rate_limit_returns_retry_after(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_RATE_LIMIT", "1")
    assert client.get("/health").status_code == 200
    blocked = client.get("/health")
    assert blocked.status_code == 429
    assert blocked.headers.get("retry-after")
    assert blocked.headers.get("x-ratelimit-remaining") == "0"


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def test_security_headers_on_api_responses(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_csp_omitted_for_docs_but_headers_remain(monkeypatch) -> None:
    monkeypatch.setenv("ENABLE_API_DOCS", "true")
    app = FastAPI(**fastapi_docs_kwargs())
    install_api_protections(app)
    client = TestClient(app)
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
    assert docs.headers["x-content-type-options"] == "nosniff"
    api_like = client.get("/health")
    assert "content-security-policy" in api_like.headers
