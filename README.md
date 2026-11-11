# Veritas Inspector

A polished, responsive AI security command center for deepfake, malicious-code, and phishing inspection workflows, with a standalone mathematical code-analysis backend.

## Frontend

The static dashboard can be served from the repository root with any static web server:

```bash
python3 -m http.server 4173 --bind 0.0.0.0
```

Then open `http://localhost:4173` in a browser.

## Mathematical analysis backend

`backend_core.py` contains the FastAPI and NumPy inspection service. It parses Python with the standard-library AST and JavaScript with a dependency-free structural lexer, then computes complexity, loop density, entropy, obfuscation, injection, and deterministic trust metrics.

Install the backend dependencies and start the API:

```bash
python3 -m pip install -r requirements.txt
python3 backend_core.py
```

The API listens on `http://localhost:8000` by default.

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
- Media forensics workspace with image/video drag-and-drop previews.
- DOM / code inspector with source and URL presets.
- Text shield for phishing and authorship signals.
- Animated deep-scan simulation with live verdict, score gauge, signal meters, and evidence log.
- Device Guardian perimeter widget, activity chart, adaptive protection toggle, toast feedback, and local report export.
- Tailwind CSS and Font Awesome loaded via CDN; app behavior is implemented in vanilla JavaScript.
- Browser-side live inspection engine recalculates AST-like complexity, loop density, Shannon entropy, obfuscation, injection, file signature, and SHA-256 signals as evidence changes.
- Real-time cyberpunk threat alerts raise an active banner, animated notification popups, visual sound-wave indicators, optional alert tones, and dismissal/review controls for malicious or suspicious findings.
