# Phase 2B — Secure backend deployment readiness

**Status:** planning and implementation preparation only.  
**Do not deploy, purchase hosting, change DNS, or publish secrets without explicit approval.**

The GitHub Pages site at `https://mohamdmamdoh83-coder.github.io/AegisCode-AI/` is static HTML/JS. It is not an API. A public analysis backend must be a separate HTTPS origin.

---

## 1. Architecture recommendation

**Recommended production shape**

```
Browser
  https://mohamdmamdoh83-coder.github.io/AegisCode-AI/
        |
        | HTTPS fetch
        | Origin: https://mohamdmamdoh83-coder.github.io
        v
Fly.io Machine  (Docker, uvicorn, 1 worker)
  GET  /health
  POST /api/v1/inspect-code
  POST /api/v1/filter-threat
```

**Why Fly.io (primary)**

- Automatic HTTPS. The first 10 single-hostname certificates are free. [Fly.io pricing](https://docs.fly.io/about/pricing)
- Secrets stay in `fly secrets`, not in the repository.
- `fly logs` and `fly machine restart` cover logs, restart, and health.
- No 32 MB HTTP/1 request ceiling. The product accepts 25 MB uploads.
- Always-on `shared-cpu-1x` with 1 GB RAM is enough for FastAPI + NumPy without a $25 Render instance.
- No monthly platform fee. Pay for the Machine.

**Why not Cloud Run as primary:** Cloud Run HTTP/1 request bodies are capped at 32 MB, which is too close to the 25 MB evidence limit once multipart overhead is included.

**Why not Render free:** free web services spin down after 15 minutes. The dashboard polls `/health` every 15 seconds and would pay that cold-start cost on every visitor. Render Starter ($7/mo, 512 MB) is a valid alternative if a GitHub-connected UI is preferred; 512 MB is tight for a 25 MB in-memory upload.

**Workers:** keep **1 uvicorn worker**. The rate limiter is in-process. Extra workers split the limit and duplicate memory for uploads.

---

## 2. Hosting comparison

| | **Fly.io (recommended)** | **Render Starter / Standard** | **Google Cloud Run** | **Railway Hobby** |
|---|---|---|---|---|
| HTTPS | Automatic; first 10 certs free | Automatic | Automatic | Automatic |
| Secrets | `fly secrets` | Dashboard env | Secret Manager | Dashboard variables |
| Logs | `fly logs`, retained on the platform | Dashboard logs | Cloud Logging | Dashboard logs |
| Restart / health | `fly machine restart`; HTTP health | Dashboard restart; health path | Revisions; `/health` | Restart service |
| Request size | Suitable for 25 MB | Suitable for 25 MB | HTTP/1 **32 MB** cap | Suitable for 25 MB |
| Idle behavior | Can autostop (optional) or stay up | Free sleeps 15 min; paid always-on | Scale to zero | Always-on while billed |
| RAM for this app | 1 GB recommended | Starter 512 MB; Standard 2 GB | Configurable | Usage-based |
| Reliability | Pay-as-you-go Machines | Git deploys, health checks | Strong, more GCP account setup | Hobby is simple; platform outage reported May 2026 |
| Est. monthly (this API) | **~$6.70–$9** always-on 1 GB + light egress | **$7** Starter (tight) or **$25** Standard 2 GB | Often ~$0–few dollars on free tier if traffic is low; 32 MB risk | **$5** minimum |

Sources: [Fly.io pricing](https://docs.fly.io/about/pricing), [Render pricing](https://render.com/pricing), [Cloud Run pricing](https://cloud.google.com/run/pricing), [Cloud Run quotas](https://cloud.google.com/run/quotas).

---

## 3. Backend production configuration (implemented)

| Setting | Production value |
|---|---|
| ASGI | `uvicorn backend_core:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*' --workers 1` |
| `ENVIRONMENT` | `production` |
| CORS | Exact origin `https://mohamdmamdoh83-coder.github.io` only. `*` is rejected. |
| Docs | `/docs`, `/redoc`, `/openapi.json` disabled unless `ENABLE_API_DOCS=true` |
| Health | `GET /health` remains unauthenticated and returns `status=ok` |
| Errors | Unhandled exceptions return `{"detail":"internal error"}` with no traceback |
| Logs | `method path status duration_ms` only. No bodies, headers, API keys, or uploads |
| Proxy | `TRUST_PROXY_HEADERS=true` **only** behind Fly/Render/Cloud Run, which overwrite `X-Forwarded-For` |

Local development is unchanged: localhost CORS, docs on, no proxy trust.

---

## 4. Authentication and abuse protection

A shared private API key **must not** be placed in GitHub Pages JavaScript. Anyone can read it.

For a public inspector UI the honest model is:

1. **Leave `API_KEY` unset** on the public API so the Pages origin can call it.
2. Restrict **browsers** with exact CORS (`https://mohamdmamdoh83-coder.github.io`).
3. Restrict **everyone** (including curl) with:
   - 60 requests / 60 seconds / client IP (override with `API_RATE_LIMIT`)
   - 25 MB / 26 MB request cap
   - 200k source-code character cap
   - 1 worker so the limiter is not split
4. Set `TRUST_PROXY_HEADERS=true` so rate limits key on the platform’s client IP, not the proxy.
5. Keep `/health` public for uptime checks. Disable API docs.

CORS does not stop curl. That is expected for a public analysis API. Do not pretend a hidden browser key is access control.

Optional later (needs approval): Cloudflare in front, Turnstile, or a signed short-lived browser token. Not in this phase.

If `API_KEY` is set in production, the public dashboard will show **AUTHENTICATION REQUIRED** and will not store or send a key.

---

## 5. Frontend integration readiness (implemented)

- Local pages still default to `http://localhost:8000`.
- GitHub Pages (`https://mohamdmamdoh83-coder.github.io`) **never** uses localhost or `http://` API URLs (mixed content blocked).
- Production URL comes from `meta[name=veritas-api-base-production]`, `?apiBase=`, `localStorage.veritas.apiBaseUrl`, or `window.VERITAS_API_BASE`, and only if it is `https://` and not loopback.
- That production meta is **empty** until you approve a live HTTPS API URL. Until then Pages shows `API NOT CONFIGURED` / unavailable — not a fake score.
- Failed calls still use `source: "error"`. Idle uses `source: "idle"`. Only mapped API payloads are `source: "backend"`.
- Error/idle gauges show **—** and **NO VERDICT**, not `0.0` as a trust score.

After a backend URL exists, set the production meta (or `?apiBase=`) to that HTTPS origin and add the same origin to `CORS_ALLOW_ORIGINS`. Do not commit secrets.

---

## 6. Evidence-log 98.4% finding

The `14:32:08 Cross-engine consensus reached **98.4%**` rows were **static HTML placeholders**, not historical backend results. They were never produced by `/api/v1/inspect-code` or `/api/v1/filter-threat`. The results panel also shipped with a fake `LOW RISK · VERIFIED` / `98.4` first paint.

**Removed** from the verdict stream and evidence log. Replaced with idle copy: `AWAITING INSPECTION`, `NO VERDICT`, `No backend verdict recorded`.

The hero visual chip that still shows **98.4% confidence index** is decorative marketing chrome, not a scan result. Layout was left unchanged.

---

## 7. Required environment variables

Set these in the host’s secret/env UI. **Do not put values in git.**

| Name | Required | Production |
|---|---|---|
| `ENVIRONMENT` | yes | `production` |
| `PORT` | platform | provided by Fly/Render |
| `CORS_ALLOW_ORIGINS` | yes | `https://mohamdmamdoh83-coder.github.io` |
| `TRUST_PROXY_HEADERS` | yes behind a proxy | `true` |
| `ENABLE_API_DOCS` | no | unset or `false` |
| `API_RATE_LIMIT` | no | `60` |
| `API_RATE_WINDOW_SECONDS` | no | `60` |
| `MAX_REQUEST_BYTES` | no | `27262976` |
| `LOG_LEVEL` | no | `INFO` |
| `API_KEY` / `VERITAS_API_KEY` | no | **leave unset** for public Pages |

`.env.example` lists the same keys with no secrets.

---

## 8. Deployment steps (do not run until approved)

### Fly.io (recommended)

1. Create a Fly account and install `flyctl`. This **will bill** if a Machine is started.
2. `fly launch --no-deploy` from this repo using the `Dockerfile`.
3. Set secrets/env (no API key for public Pages):

   ```bash
   fly secrets set ENVIRONMENT=production \
     CORS_ALLOW_ORIGINS=https://mohamdmamdoh83-coder.github.io \
     TRUST_PROXY_HEADERS=true \
     ENABLE_API_DOCS=false \
     API_RATE_LIMIT=60
   ```

4. Size: `shared-cpu-1x`, **1024 MB** RAM, 1 Machine, auto-start on, auto-stop off for a public dashboard.
5. Health check: `GET /health`.
6. `fly deploy` **only after approval**.
7. Confirm `https://<app>.fly.dev/health` returns `{"status":"ok",...}`.
8. Put that HTTPS origin in `veritas-api-base-production` and ship a frontend commit.

### Render alternative

1. New **Web Service**, Docker or native Python.
2. Start command = `Procfile` / uvicorn line above.
3. Instance: Standard **2 GB** if choosing Render; Starter 512 MB is a last resort.
4. Health check path `/health`.
5. Same env vars. Do not enable a public `*.onrender.com` CORS wildcard.

### Health-check procedure

```bash
curl -sS https://<api-host>/health
# expect: "status":"ok"
curl -sS -D- -o /dev/null -X OPTIONS https://<api-host>/api/v1/inspect-code \
  -H "Origin: https://mohamdmamdoh83-coder.github.io" \
  -H "Access-Control-Request-Method: POST"
# expect: access-control-allow-origin: https://mohamdmamdoh83-coder.github.io
```

From the Pages dashboard: status chip `API CONNECTED`, then a deep scan on a small Python snippet. Failed HTTPS must show `NO VERDICT`, never a numeric mock score.

### Rollback

1. Fly: `fly releases` then `fly deploy --image <previous>` or `fly machine rollback` for the last healthy release.
2. Render: dashboard → previous successful deploy → **Rollback**.
3. Frontend: revert the production API meta to empty so Pages stops calling a bad origin (honest unconfigured state).
4. DNS: none in this plan (use `*.fly.dev` / `*.onrender.com` until a custom domain is approved).

---

## 9. Estimated operating costs

Assumes one always-on API, no database, GitHub Pages remaining free.

| Option | Compute | Extra | Monthly ballpark |
|---|---|---|---|
| **Fly.io shared-cpu-1x 1 GB** (recommended) | $6.70 / 30 days in iad/ewr | Shared IPv4 free; ~10 GB NA egress $0.20; first 10 certs free | **~$7–9** |
| Fly.io shared-cpu-1x 512 MB | $3.69 | Same | **~$4–6** (memory risk on 25 MB uploads) |
| Render Starter 0.5 CPU / 512 MB | $7 | Hobby workspace $0; 5 GB bandwidth included | **$7** (tight RAM) |
| Render Standard 1 CPU / 2 GB | $25 | Same | **$25** |
| Cloud Run request-based, us-central1 | Free tier: 2M requests, 180k vCPU-s, 360k GiB-s | 32 MB request risk | **~$0–5** at low traffic |
| Railway Hobby | $5 minimum | Usage above the included credit | **$5+** |

Sources:

- Fly Machines: [https://docs.fly.io/about/pricing](https://docs.fly.io/about/pricing) (`shared-cpu-1x` 512 MB $3.69, 1 GB $6.70; egress $0.02/GB NA/EU).
- Render compute: [https://render.com/pricing](https://render.com/pricing) (Starter $7 / 512 MB / 0.5 CPU; 1 CPU 2 GB $25; Hobby $0 + compute).
- Cloud Run: [https://cloud.google.com/run/pricing](https://cloud.google.com/run/pricing) (2M requests, 180,000 vCPU-seconds, 360,000 GiB-seconds free / month, request-based).

These are list prices, not quotes. Confirm on the provider page before paying.

---

## 10. Security risks remaining after this phase

| Risk | Mitigation now | Residual |
|---|---|---|
| Public unauthenticated API | CORS + rate limit + size caps | curl can still call the API |
| Upload of malware samples | Not executed; hashed/inspected only | Operator still receives attacker-chosen bytes |
| In-process rate limit | 1 worker | Multi-instance needs a gateway |
| `TRUST_PROXY_HEADERS` spoofing | Enable only behind Fly/Render | Do not set on a raw VM without a stripping proxy |
| Mixed content / localhost on Pages | Client refuses loopback and `http://` on https pages | Operator must set a real HTTPS URL |
| API docs leak | Disabled in production | Do not set `ENABLE_API_DOCS=true` publicly |
| Tailwind / Font Awesome CDN | Unchanged | No SRI (pre-existing) |
| Hero “98.4% confidence” chip | Not a verdict | Decorative only |
| No backend live today | Pages shows unconfigured/unavailable | Not a production integration until you approve hosting |

---

## 11. Deployment checklist (after approval)

- [ ] Hosting account created (Fly.io recommended)
- [ ] Billing acknowledged
- [ ] `Dockerfile` build succeeds locally (optional smoke, not a deploy)
- [ ] Env vars set in the provider UI, not in git
- [ ] `API_KEY` left unset for public Pages
- [ ] `CORS_ALLOW_ORIGINS=https://mohamdmamdoh83-coder.github.io`
- [ ] `TRUST_PROXY_HEADERS=true`
- [ ] Docs disabled
- [ ] `GET /health` 200 over HTTPS
- [ ] CORS preflight from the Pages origin succeeds
- [ ] Unknown origin is not reflected
- [ ] Oversized upload still 413
- [ ] Rate limit still 429
- [ ] Frontend production meta set to the HTTPS API origin
- [ ] Pages deep scan returns `source: backend` or an honest error
- [ ] Rollback path verified (`fly releases` or Render rollback)
- [ ] Custom domain / DNS **not** changed unless separately approved

---

## 12. Actions that require your approval

1. Create a Fly.io, Render, Cloud Run, or Railway account and attach billing.
2. Run `fly deploy`, Render deploy, `gcloud run deploy`, or any public bind of this API.
3. Put a real HTTPS URL into `veritas-api-base-production`.
4. Set `API_KEY` (this will 401 the public dashboard unless a non-browser client is intended).
5. Enable `ENABLE_API_DOCS=true` on a public host.
6. Add Cloudflare, a custom domain, or DNS records.
7. Raise or remove the 25 MB / rate-limit caps.
8. Allow additional CORS origins.
9. Merge this branch (not done in Phase 2B).
10. Start Phase 3.
