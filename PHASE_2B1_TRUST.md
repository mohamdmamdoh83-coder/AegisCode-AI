# Phase 2B.1 — Trust and abuse review

Readiness notes only. **Do not deploy without approval.**

## Supported hosting for `TRUST_PROXY_HEADERS=true`

Enable trusted-proxy client IPs **only** when the process sits behind a platform proxy that **overwrites** `X-Forwarded-For`. The Dockerfile and Procfile assume that.

| Environment | Supported? | Why |
|---|---|---|
| **Fly.io Machine** (recommended) | Yes | Fly’s proxy terminates TLS and sets `X-Forwarded-For` to the client. Pair with `--proxy-headers --forwarded-allow-ips='*'`. |
| **Render Web Service** | Yes | Render’s reverse proxy overwrites forwarded headers the same way. |
| **Google Cloud Run** | Conditional | GFE sets `X-Forwarded-For`, but HTTP/1 request bodies are capped at **32 MB** — too close to the 25 MB upload limit. Not the primary target. |
| Raw VM / `uvicorn` on `0.0.0.0` | **No** | Clients can send a fake `X-Forwarded-For` and bypass per-IP rate limits. Leave `TRUST_PROXY_HEADERS` unset. |
| CDN that **appends** rather than overwrites the header | **No** unless you pin the exact proxy hop | First-IP parsing would trust the client-supplied address. |

Exact production shape this repo is prepared for:

```text
https://mohamdmamdoh83-coder.github.io  (GitHub Pages, static)
        HTTPS, Origin: https://mohamdmamdoh83-coder.github.io
        v
Fly.io proxy  →  uvicorn backend_core:app  (1 worker, ENVIRONMENT=production)
```

Do not set `API_KEY` if the public Pages UI must call the API. Do not put any key in browser JavaScript.

## Public API abuse protections (current code)

| Control | Value | Notes |
|---|---|---|
| Rate limit | **60 requests / 60 seconds / client** | In-process. Includes `/health`. Dashboard polls health every 15 s (4/min), leaving headroom for scans. Shared NATs share one bucket. |
| Request body | **26,214,272 bytes** (`26 * 1024 * 1024`) | Enforced from `Content-Length` and from streamed chunk totals. |
| Upload | **25 MB** decoded file | Rejected in the UI, the JS client, and the server before full decode. |
| Source code | **200,000 characters** | Client and `/api/v1/inspect-code`. |
| URL | **8,192 characters** | Client and filter-threat. |
| CORS | Exact origin allowlist | `*` is rejected. Production default: `https://mohamdmamdoh83-coder.github.io`. CORS does **not** stop curl. |
| Workers | **1** | Extra workers split the in-memory limiter and duplicate upload buffers. |
| Docs | Off in production | `/docs`, `/redoc`, `/openapi.json` are not mounted. |
| Auth | Optional env key | Browser cannot hold a private key. Leave unset for Pages. |

## Memory

A 25 MB upload is buffered in process memory (multipart + decoded bytes + analysis structures). NumPy scoring adds copies. **1 GB RAM** is the minimum this review will call safe. A 512 MB Fly/Render starter instance can OOM on a max-size file.

## Logging and monitoring (recommendations, not deployed)

Already implemented:

- Access log: `method path status duration_ms` only.
- No request bodies, headers, API keys, or file bytes.
- Unhandled errors: client sees `{"detail":"internal error"}`; server logs exception type + path.

After a host exists (needs approval), watch:

- `GET /health` every 15 s from Pages (liveness).
- Platform logs (`fly logs` / Render logs) for 429, 413, 5xx spikes.
- Process RSS near the 1 GB cap.
- Rate-limit 429s from a single IP (abuse) vs many IPs (shared NAT).

No metrics backend is shipped in this phase.

## UI honesty (this change)

- Hero **98.4% confidence index** removed. That chip now mirrors real API health (`CONNECTING` / `API CONNECTED` / `API NOT CONFIGURED` / errors). It is not a scan score.
- Bottom hero chip no longer says **NO ACTIVE THREATS**. It labels the Pages host as a static frontend.
- Verdict stream: **idle** (cyan, `—`, `NO VERDICT`), **error** (dashed, `—`, `NO VERDICT`), **backend** (`TRUST SCORE` + `SECURE` / `REVIEW_REQUIRED` / `MALICIOUS`). Connecting stays on the header/hero health chip only.
