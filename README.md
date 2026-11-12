# Veritas Inspector

A static dashboard for heuristic inspection of Python/JavaScript source, file integrity, and URL phishing signals, with a standalone mathematical analysis backend. It does not detect deepfakes or authorship.

## Frontend

The static dashboard can be served from the repository root with any static web server:

```bash
python3 -m http.server 4173 --bind 0.0.0.0
```

Then open `http://localhost:4173` in a browser.

The dashboard calls the analysis API at `http://localhost:8000` by default (`GET /health`, `POST /api/v1/inspect-code`, `POST /api/v1/filter-threat`). Override the local base URL with the `veritas-api-base` meta tag, `?apiBase=`, `localStorage.veritas.apiBaseUrl`, or `window.VERITAS_API_BASE`. On GitHub Pages (or any public HTTPS origin) the client never uses localhost or mixed `http://` API URLs. Set `veritas-api-base-production` to a future HTTPS API origin after that host is approved. The browser client never sends or stores API keys; if the backend requires a key, the UI reports authentication required instead of a fake verdict. Failed or unconfigured API calls show **NO VERDICT**, not a numeric mock score.

The analysis API is **not hosted** in this repository's GitHub Pages deployment. See `PHASE_2B_DEPLOYMENT.md` before any public backend is created. Do not deploy it without approval.

## Mathematical analysis backend

`backend_core.py` contains the FastAPI and NumPy inspection service. It parses Python with the standard-library AST and JavaScript with a dependency-free structural lexer, then computes complexity, loop density, entropy, obfuscation, injection, and deterministic trust metrics.

Install the backend dependencies and start the API:

```bash
python3 -m pip install -r requirements.txt
python3 backend_core.py
```

The API listens on `http://localhost:8000` by default.

### API protections

Both `backend_core.py` and standalone `threat_filter_core.py` apply environment-driven controls:

- `CORS_ALLOW_ORIGINS` — comma-separated origins. Wildcard `*` is rejected. Development defaults to local dashboard/API ports. Production defaults to `https://mohamdmamdoh83-coder.github.io`.
- `ENVIRONMENT=production` — disables `/docs`, `/redoc`, and `/openapi.json` unless `ENABLE_API_DOCS=true`.
- `API_KEY`, `VERITAS_API_KEY`, or `AEGIS_API_KEY` — when set, require `X-API-Key` or `Authorization: Bearer`. `/health` remains unauthenticated. **Do not put this key in browser JavaScript.** Leave it unset for a public GitHub Pages frontend.
- `API_RATE_LIMIT` / `API_RATE_WINDOW_SECONDS` — per-client request budget (default 60/minute). `0` disables the limiter. Use one uvicorn worker so the in-process limiter is not split.
- `TRUST_PROXY_HEADERS=true` — only behind Fly/Render/Cloud Run so rate limits use `X-Forwarded-For`.
- Uploads are rejected at **25 MB** before the file is fully decoded. The dashboard evidence limit matches this size.
- Production start: `uvicorn backend_core:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*' --workers 1`. See `Dockerfile` and `.env.example`.

Standalone threat filtering:

```bash
python3 threat_filter_core.py
curl http://localhost:8001/health
```

### Inspect code

```bash
curl -X POST http://localhost:8000/api/v1/inspect-code \\
  -H 'content-type: application/json' \\
  -d '{"language":"python","source_code":"def add(a, b):\\n    return a + b"}'
```

The response includes `trust_score`, `verification_status` (`SECURE`, `REVIEW_REQUIRED`, or `MALICIOUS`), `confidence_index`, normalized threat breakdowns, syntax anomalies, metrics, and analysis logs. Syntax errors are returned as evidence with conservative scoring rather than causing a server error.

## Threat filtering core

`threat_filter_core.py` adds a modular, read-only endpoint-protection pipeline. It hashes and inspects file or binary payloads, checks PE/ELF/Mach-O headers and script structure, analyzes URLs and network payloads for phishing and injection patterns, and scores caller-provided process snapshots for memory injection and suspicious command lines.

The same service exposes:

```text
POST /api/v1/filter-threat
```

JSON requests can contain `file_content_base64` plus `file_name`, `source_code` or `code`, `url`, `network_payload`, and `processes`. Multipart file uploads and raw `application/octet-stream` uploads are also accepted. Every response returns an immediate `ALLOW`, `QUARANTINE`, or `BLOCK` action, a 0–100 threat level index, confidence, component reports, hashes, indicators, policy reasons, and structured forensic logs. No submitted file is executed and no external reputation service is contacted.

Example URL inspection:

```bash
curl -X POST http://localhost:8000/api/v1/filter-threat \\
  -H 'content-type: application/json' \\
  -d '{"payload_type":"url","url":"https://secure-login.example.top/verify?redirect=https%3A%2F%2Fevil.example"}'
```

## Included

- Futuristic dark-mode dashboard with responsive mobile navigation.
- File inspection workspace with image/video drag-and-drop previews. The API hashes files and checks headers/entropy; it does not classify deepfakes.
- DOM / code inspector with source and URL presets.
- Text shield for URL phishing only. Free-form text without a URL is not scored and never receives a fabricated verdict.
- Deep scan against the local analysis API with live verdict, score gauge, signal meters, and evidence log. Idle and error states are labeled as not backend verdicts.
- Device Guardian perimeter widget and activity chart are demonstration layout only. Adaptive protection toggle, toast feedback, and local report export remain local UI.
- Tailwind CSS and Font Awesome loaded via CDN; app behavior is implemented in vanilla JavaScript.
- Real-time cyberpunk threat alerts raise an active banner, animated notification popups, visual sound-wave indicators, optional alert tones, and dismissal/review controls for malicious or suspicious **backend** findings.
