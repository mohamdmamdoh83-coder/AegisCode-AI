"""Frontend / backend integration tests for Phase 2A."""

from __future__ import annotations

import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def test_frontend_loads_api_client_without_secrets() -> None:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    api_js = (ROOT / "api.js").read_text(encoding="utf-8")
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    assert 'src="api.js"' in html
    assert 'name="veritas-api-base"' in html
    assert "http://localhost:8000" in html
    for forbidden in ("API_KEY=", "VERITAS_API_KEY=", "AEGIS_API_KEY=", "X-API-Key:"):
        assert forbidden not in api_js
        assert forbidden not in app_js
        assert forbidden not in html


def test_frontend_does_not_present_mock_verdicts() -> None:
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "modeCopy" not in app_js
    assert "analyzeCodeEvidence" not in app_js
    assert "inspectMediaFile" not in app_js
    assert "HIGH RISK · SYNTHETIC MEDIA" not in app_js
    assert "Generative artifacts strongly detected" not in app_js
    assert "inspectCurrentEvidence" in app_js
    assert "VeritasAPI" in app_js
    assert "errorResult" in app_js
    assert "idleResult" in app_js
    log_start = html.find('id="logList"')
    assert log_start != -1
    log_html = html[log_start : log_start + 800]
    assert "98.4%" not in log_html
    assert "Cross-engine consensus reached" not in log_html
    assert "Compared against 2.84M forensic signals" not in html[html.find('id="logList"') :]
    assert "No backend verdict recorded" in log_html
    assert 'id="scoreValue">—</span>' in html
    assert "LOW RISK · VERIFIED" not in html
    assert "AWAITING INSPECTION" in html
    assert 'name="veritas-api-base-production"' in html
    assert "98.4" not in html
    assert "confidence index" not in html
    assert "NO ACTIVE THREATS" not in html
    assert 'id="heroApiStatus"' in html
    assert "STATIC FRONTEND" in html
    assert 'data-source="idle"' in html
    assert "result-status idle" in app_js or 'result-status ${source}' in app_js


def test_health_and_inspect_and_filter_endpoints(client: TestClient) -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    inspected = client.post(
        "/api/v1/inspect-code",
        json={"language": "python", "source_code": "def add(a, b):\n    return a + b\n"},
    )
    assert inspected.status_code == 200
    body = inspected.json()
    assert body["verification_status"] in {"SECURE", "REVIEW_REQUIRED", "MALICIOUS"}
    assert "trust_score" in body

    filtered = client.post(
        "/api/v1/filter-threat",
        json={"payload_type": "url", "url": "https://example.com/"},
    )
    assert filtered.status_code == 200
    threat = filtered.json()
    assert threat["action"] in {"ALLOW", "QUARANTINE", "BLOCK"}
    assert "threat_level_index" in threat


def test_api_js_node_suite() -> None:
    script = ROOT / "tests" / "test_api_client.js"
    completed = subprocess.run(
        ["node", str(script)],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "api.js client tests passed" in completed.stdout


def test_mapper_accepts_live_inspect_payload(client: TestClient) -> None:
    response = client.post(
        "/api/v1/inspect-code",
        json={"language": "javascript", "source_code": "const x = 1;\n"},
    )
    assert response.status_code == 200
    payload = response.json()
    node = subprocess.run(
        [
            "node",
            "-e",
            "const api=require('./api.js'); const mapped=api.mapInspectCode(JSON.parse(process.argv[1])); if (mapped.source!=='backend') process.exit(2);",
            __import__("json").dumps(payload),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert node.returncode == 0, node.stdout + node.stderr


def test_phase1_truth_claims_are_not_advertised() -> None:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    css = (ROOT / "styles.css").read_text(encoding="utf-8")

    assert "AES-256" not in html
    assert "AES-256" not in app_js
    assert "42 languages" not in html
    assert "No client-side encryption" in html
    assert "DEVICE GUARDIAN · DEMO" in html
    assert "DEMO · NETWORK PULSE" in html
    assert "URL phishing only" in html
    assert "does not detect deepfakes" in html
    assert "Deepfake artifact signature detected" not in app_js
    assert "generativeArtifactIndex" not in app_js
    assert "File integrity warning" in app_js
    assert "Suspicious file characteristics require review" in app_js
    assert "does not detect deepfakes" in readme
    assert "demonstration layout only" in readme
    assert ".signal-icon.danger" in css
    assert "danger-meter" in css
    assert "danger-meter" in app_js


def test_phase1_text_mode_requires_url() -> None:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    assert 'id="textUrlInput"' in html
    assert "readInspectionUrl" in app_js
    assert "textUrlInput" in app_js
    assert "https://account-verification.example.com/session/continue" in app_js
    assert "URL scan is disabled until a URL is supplied" in app_js
    assert "Provide a URL to run /api/v1/filter-threat" in app_js
    assert "not authorship" in app_js


def test_phase1_object_urls_are_revoked() -> None:
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    assert "replacePreviewObjectUrl" in app_js
    assert "URL.createObjectURL(file)" in app_js
    assert "URL.revokeObjectURL(previous)" in app_js
    assert app_js.count("URL.revokeObjectURL") >= 2


def test_phase1_health_poll_requires_configured_api() -> None:
    app_js = (ROOT / "app.js").read_text(encoding="utf-8")
    assert "function startHealthPolling" in app_js
    assert "startHealthPolling();" in app_js
    assert "api().isConfigured()" in app_js
    assert "window.setInterval(pollBackendHealth, 15000)" in app_js
    init_start = app_js.find("function init()")
    init_end = app_js.find("function bindNavigation()")
    init_fn = app_js[init_start:init_end]
    assert "setInterval" not in init_fn
    assert "startHealthPolling" in init_fn
    assert "API NOT CONFIGURED" in app_js
