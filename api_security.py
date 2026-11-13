"""Shared API protection middleware for Veritas Inspector services.

The helpers in this module are intentionally small and dependency-free beyond
FastAPI/Starlette.  They wrap both ``backend_core.app`` and the standalone
``threat_filter_core.app`` with:

* environment-driven CORS
* optional API-key authentication
* in-process per-client rate limiting
* request-body size enforcement before handlers allocate large buffers

None of these controls is a stub: when an API key is configured it is compared
in constant time, oversized bodies are rejected, and rate-limit counters are
enforced.  Secrets are never written to logs or response bodies.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Iterable, Optional

from starlette.types import ASGIApp, Receive, Scope, Send


logger = logging.getLogger("veritas.api")

DEFAULT_CORS_ORIGINS = (
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
)
PRODUCTION_CORS_ORIGINS = (
    "https://mohamdmamdoh83-coder.github.io",
)
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW_SECONDS = 60
DEFAULT_MAX_REQUEST_BYTES = 26 * 1024 * 1024
_MAX_TRACKED_CLIENTS = 10_000
_AUTH_EXEMPT_PATHS = {"/health"}
_AUTH_EXEMPT_PREFIXES: tuple[str, ...] = ()

_rate_hits: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = Lock()
_redis_client_singleton: Any = None
_redis_fallback_logged = False


def reset_security_state() -> None:
    """Clear rate-limit buckets and the optional Redis client.  Tests only."""

    global _redis_client_singleton, _redis_fallback_logged
    with _rate_lock:
        _rate_hits.clear()
    _redis_client_singleton = None
    _redis_fallback_logged = False


def is_production() -> bool:
    """True when ENVIRONMENT or VERITAS_ENV is production/prod."""

    value = os.environ.get("ENVIRONMENT", os.environ.get("VERITAS_ENV", "development"))
    return str(value).strip().lower() in {"production", "prod"}


def configured_environment() -> str:
    return "production" if is_production() else "development"


def api_docs_enabled() -> bool:
    """OpenAPI/Swagger are on in development and off in production unless overridden."""

    raw = os.environ.get("ENABLE_API_DOCS")
    if raw is not None and raw.strip():
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return not is_production()


def fastapi_docs_kwargs() -> dict[str, Optional[str]]:
    """Extra FastAPI() kwargs that hide /docs, /redoc, and /openapi.json."""

    if api_docs_enabled():
        return {}
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}


def configure_logging() -> None:
    """Idempotent process logging.  Never attaches handlers that dump request bodies."""

    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
    logging.getLogger("veritas").setLevel(level)


def configured_api_key() -> str:
    """Return the optional API key from the process environment.

    Checked names, in order: ``API_KEY``, ``VERITAS_API_KEY``, ``AEGIS_API_KEY``.
    An empty value disables authentication.
    """

    for name in ("API_KEY", "VERITAS_API_KEY", "AEGIS_API_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return ""


def configured_rate_limit() -> tuple[int, float]:
    """Return ``(max_requests, window_seconds)``.  A non-positive limit disables enforcement."""

    try:
        limit = int(os.environ.get("API_RATE_LIMIT", str(DEFAULT_RATE_LIMIT)))
    except ValueError:
        limit = DEFAULT_RATE_LIMIT
    try:
        window = float(os.environ.get("API_RATE_WINDOW_SECONDS", str(DEFAULT_RATE_WINDOW_SECONDS)))
    except ValueError:
        window = float(DEFAULT_RATE_WINDOW_SECONDS)
    return limit, max(1.0, window)


def configured_max_request_bytes() -> int:
    try:
        value = int(os.environ.get("MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES)))
    except ValueError:
        value = DEFAULT_MAX_REQUEST_BYTES
    return max(1024, value)


def configured_cors_origins() -> list[str]:
    """Return an explicit origin allowlist.  Wildcard CORS is never enabled."""

    raw = os.environ.get("CORS_ALLOW_ORIGINS")
    defaults = list(PRODUCTION_CORS_ORIGINS) if is_production() else list(DEFAULT_CORS_ORIGINS)
    if raw is None:
        return defaults
    origins = [origin.strip() for origin in raw.split(",") if origin.strip() and origin.strip() != "*"]
    if "*" in {item.strip() for item in raw.split(",") if item.strip()}:
        logger.warning("wildcard CORS origin rejected; using an explicit allowlist")
    return origins or defaults


def configured_cors_methods() -> list[str]:
    raw = os.environ.get("CORS_ALLOW_METHODS", "GET,POST,OPTIONS")
    methods = [item.strip().upper() for item in raw.split(",") if item.strip()]
    return methods or ["GET", "POST", "OPTIONS"]


def configured_cors_headers() -> list[str]:
    raw = os.environ.get("CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-API-Key")
    headers = [item.strip() for item in raw.split(",") if item.strip()]
    return headers or ["Authorization", "Content-Type", "X-API-Key"]


def _header_map(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        headers[key.decode("latin-1").lower()] = value.decode("latin-1")
    return headers


def configured_trusted_proxies() -> list[str]:
    """Peer IPs/CIDRs whose ``X-Forwarded-For`` we honor.

    Defaults to loopback only.  Deployments behind Fly/Render/Cloud Run must
    set ``TRUSTED_PROXY_IPS`` to the platform's proxy addresses so client-IP
    detection (and therefore rate limiting) works, while spoofed
    ``X-Forwarded-For`` headers from arbitrary clients are ignored.
    """

    raw = os.environ.get("TRUSTED_PROXY_IPS", "127.0.0.1,::1")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _ip_in_trusted_proxies(peer: str, proxies: Iterable[str]) -> bool:
    """True when ``peer`` matches one of the configured IPs or CIDR ranges."""

    import ipaddress

    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in proxies:
        try:
            if "/" in entry:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _client_key(scope: Scope, headers: dict[str, str]) -> str:
    """Stable per-client identity for rate limiting.

    ``X-Forwarded-For`` is only consulted when (a) TRUST_PROXY_HEADERS is
    enabled and (b) the direct peer is a configured trusted proxy.  Otherwise
    the header is attacker-controlled and would let clients rotate identities
    to evade rate limits.
    """

    client = scope.get("client")
    peer = str(client[0]) if client and client[0] else ""
    trust_proxy = os.environ.get("TRUST_PROXY_HEADERS", "").strip().lower() in {"1", "true", "yes"}
    if trust_proxy and peer and _ip_in_trusted_proxies(peer, configured_trusted_proxies()):
        forwarded = headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip() or "unknown"
    return peer or "unknown"


def _path_is_auth_exempt(path: str) -> bool:
    if path in _AUTH_EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _AUTH_EXEMPT_PREFIXES)


def _extract_provided_api_key(headers: dict[str, str]) -> str:
    header_key = headers.get("x-api-key", "").strip()
    if header_key:
        return header_key
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _api_key_matches(provided: str, expected: str) -> bool:
    """Constant-time comparison that never logs either value."""

    provided_bytes = provided.encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if len(provided_bytes) != len(expected_bytes):
        hmac.compare_digest(expected_bytes, expected_bytes)
        return False
    return hmac.compare_digest(provided_bytes, expected_bytes)


def _log_redis_fallback(reason: str) -> None:
    global _redis_fallback_logged
    if not _redis_fallback_logged:
        logger.warning("distributed rate limiting unavailable (%s); using in-process limiter", reason)
        _redis_fallback_logged = True


def _get_redis_client() -> Any:
    """Optional shared rate-limit backend selected by ``REDIS_URL``.

    ``redis`` is an optional dependency: when the package is missing, the
    server is unreachable, or no URL is configured, this returns ``None`` and
    the in-process limiter keeps protecting the worker (safe fallback).
    """

    global _redis_client_singleton
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        return None
    if _redis_client_singleton is not None:
        return _redis_client_singleton
    try:
        import redis  # type: ignore  # optional dependency
    except ImportError:
        _log_redis_fallback("redis package not installed")
        return None
    try:
        client = redis.Redis.from_url(
            url,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )
        client.ping()
    except Exception:
        _log_redis_fallback("redis unreachable")
        return None
    _redis_client_singleton = client
    return client


def _allow_rate_redis(client: Any, client_key: str, limit: int, window: float) -> tuple[bool, int]:
    key = f"veritas:rate:{client_key}:{int(window)}"
    count = int(client.incr(key))
    if count == 1:
        client.expire(key, int(window) + 1)
    remaining = max(0, limit - count)
    return count <= limit, remaining


def _allow_rate_memory(client_key: str, limit: int, window: float) -> tuple[bool, int]:
    now = time.monotonic()
    cutoff = now - window
    with _rate_lock:
        if len(_rate_hits) > _MAX_TRACKED_CLIENTS:
            # Bound memory under a noisy client-ID flood; drop the oldest half.
            for stale_key in list(_rate_hits.keys())[: len(_rate_hits) // 2]:
                _rate_hits.pop(stale_key, None)
        bucket = _rate_hits[client_key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        remaining = max(0, limit - len(bucket))
        if remaining <= 0:
            return False, 0
        bucket.append(now)
        return True, remaining - 1


def _allow_rate(client_key: str, limit: int, window: float) -> tuple[bool, int]:
    """Fixed-window limiter.  Redis when configured, in-process otherwise.

    Both paths are safe; a Redis failure at any point degrades to the
    in-process limiter for that request instead of failing open or closed.
    """

    if limit <= 0:
        return True, limit
    client = _get_redis_client()
    if client is not None:
        try:
            return _allow_rate_redis(client, client_key, limit, window)
        except Exception:
            _log_redis_fallback("redis error")
    return _allow_rate_memory(client_key, limit, window)


async def _send_json(
    send: Send,
    status: int,
    detail: str,
    extra_headers: Optional[Iterable[tuple[bytes, bytes]]] = None,
) -> None:
    payload = json.dumps({"detail": detail}).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


class MaxBodySizeMiddleware:
    """Reject request bodies that exceed the configured byte limit.

    ``Content-Length`` is enforced before any downstream handler runs so a
    client cannot force a large allocation by advertising a small length and
    then streaming more bytes: the wrapped ``receive`` channel also counts
    chunk sizes and aborts when the running total crosses the limit.
    """

    def __init__(self, app: ASGIApp, max_bytes: Optional[int] = None) -> None:
        self.app = app
        self._max_bytes = max_bytes

    @property
    def max_bytes(self) -> int:
        return self._max_bytes if self._max_bytes is not None else configured_max_request_bytes()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") in {"GET", "HEAD", "OPTIONS"}:
            await self.app(scope, receive, send)
            return

        max_bytes = self.max_bytes
        headers = _header_map(scope)
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                announced = int(content_length)
            except ValueError:
                await _send_json(send, 400, "invalid content-length header")
                return
            if announced < 0:
                await _send_json(send, 400, "invalid content-length header")
                return
            if announced > max_bytes:
                await _send_json(
                    send,
                    413,
                    f"request body exceeds the {max_bytes:,}-byte limit",
                )
                return

        received = 0
        response_started = False

        async def receive_wrapper() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                received += len(body)
                if received > max_bytes:
                    raise _BodyTooLarge()
            return message

        async def send_wrapper(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except _BodyTooLarge:
            if not response_started:
                await _send_json(
                    send,
                    413,
                    f"request body exceeds the {max_bytes:,}-byte limit",
                )


class _BodyTooLarge(Exception):
    """Internal control-flow signal used by :class:`MaxBodySizeMiddleware`."""


class RateLimitMiddleware:
    """Fixed-window per-client rate limiter.

    The limiter is process-local.  Multi-worker deployments should place a
    shared gateway in front of the API; this middleware still protects a
    single worker from abusive request rates.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        limit, window = configured_rate_limit()
        if limit <= 0:
            await self.app(scope, receive, send)
            return
        headers = _header_map(scope)
        allowed, remaining = _allow_rate(_client_key(scope, headers), limit, window)
        if not allowed:
            retry_after = str(int(window))
            await _send_json(
                send,
                429,
                "rate limit exceeded",
                extra_headers=[
                    (b"retry-after", retry_after.encode("ascii")),
                    (b"x-ratelimit-limit", str(limit).encode("ascii")),
                    (b"x-ratelimit-remaining", b"0"),
                ],
            )
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers") or [])
                raw_headers.append((b"x-ratelimit-limit", str(limit).encode("ascii")))
                raw_headers.append((b"x-ratelimit-remaining", str(remaining).encode("ascii")))
                message = {**message, "headers": raw_headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class AccessLogMiddleware:
    """Log method, path, status, and duration.  Never logs bodies, headers, or secrets."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status_box = {"status": 0}

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_box["status"] = int(message.get("status") or 0)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            logger.info(
                "request method=%s path=%s status=%s duration_ms=%s",
                scope.get("method") or "",
                scope.get("path") or "",
                status_box["status"],
                duration_ms,
            )


class SecurityHeadersMiddleware:
    """Attach conservative security headers to every response.

    The services return JSON (plus optional dev docs), so a tight
    ``default-src 'none'`` CSP is safe and blocks content sniffing, framing,
    and referrer leakage.  Doc pages get no CSP so Swagger UI keeps rendering.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        is_doc_page = path.startswith("/docs") or path.startswith("/redoc")

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers") or [])
                present = {name.lower() for name, _ in raw_headers}

                def put(name: str, value: str) -> None:
                    if name not in present:
                        raw_headers.append((name.encode("latin-1"), value.encode("latin-1")))

                put("x-content-type-options", "nosniff")
                put("x-frame-options", "DENY")
                put("referrer-policy", "no-referrer")
                put("cache-control", "no-store")
                put("permissions-policy", "camera=(), microphone=(), geolocation=()")
                if not is_doc_page:
                    put("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
                message = {**message, "headers": raw_headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class ApiKeyMiddleware:
    """Optional API-key gate.

    When no key is configured the middleware is a no-op so local analysis
    workflows keep working.  When a key is configured, every non-exempt
    request must present it via ``X-API-Key`` or ``Authorization: Bearer``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        if _path_is_auth_exempt(path):
            await self.app(scope, receive, send)
            return
        expected = configured_api_key()
        if not expected:
            await self.app(scope, receive, send)
            return
        headers = _header_map(scope)
        provided = _extract_provided_api_key(headers)
        if not provided or not _api_key_matches(provided, expected):
            await _send_json(send, 401, "invalid or missing API key")
            return
        await self.app(scope, receive, send)


def install_api_protections(app: Any, *, max_body_bytes: Optional[int] = None) -> None:
    """Attach CORS, body-size, rate-limit, and API-key middleware to ``app``.

    Middleware is added so CORS is outermost and still annotates 401/413/429
    responses generated by the inner protections.
    """

    if getattr(getattr(app, "state", None), "api_protections_installed", False):
        return

    from fastapi.middleware.cors import CORSMiddleware

    configure_logging()
    origins = configured_cors_origins()
    allow_credentials = "*" not in origins
    app.add_middleware(ApiKeyMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_body_bytes)
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=configured_cors_methods(),
        allow_headers=configured_cors_headers(),
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
        max_age=600,
    )
    _install_safe_exception_handlers(app)
    try:
        app.state.api_protections_installed = True
    except Exception:
        pass


def _install_safe_exception_handlers(app: Any) -> None:
    """Return generic 500 bodies in production and never echo exception text."""

    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled_error method=%s path=%s type=%s",
            request.method,
            request.url.path,
            type(exc).__name__,
        )
        return JSONResponse({"detail": "internal error"}, status_code=500)
