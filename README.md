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

## Included

- Futuristic dark-mode dashboard with responsive mobile navigation.
- Media forensics workspace with image/video drag-and-drop previews.
- DOM / code inspector with source and URL presets.
- Text shield for phishing and authorship signals.
- Animated deep-scan simulation with live verdict, score gauge, signal meters, and evidence log.
- Device Guardian perimeter widget, activity chart, adaptive protection toggle, toast feedback, and local report export.
- Tailwind CSS and Font Awesome loaded via CDN; app behavior is implemented in vanilla JavaScript.
