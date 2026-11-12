"""Python/JavaScript parsing, XSS preservation, and existing-behavior regression."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from backend_core import _javascript_lexemes, analyze_code
from threat_filter_core import ThreatFilterEngine, run_threat_filter, ThreatFilterInput, ThreatFilterRequest


ROOT = Path(__file__).resolve().parents[1]

JS_SAMPLE = """const observer = new MutationObserver((records) => {
  records.forEach(({ target }) => {
    if (target.dataset.aiInjected === 'true') {
      console.warn('Unexpected DOM mutation detected');
    }
  });
});
observer.observe(document.body, { subtree: true, attributes: true });
"""

PYTHON_SAMPLE = """def add(a, b):
    return a + b
"""


def test_python_analysis_secure_for_simple_function() -> None:
    result = analyze_code(PYTHON_SAMPLE, "python")
    assert result.language == "python"
    assert result.syntax_errors == []
    assert result.verification_status == "SECURE"
    assert result.trust_score >= 75


def test_python_syntax_error_is_evidence_not_crash() -> None:
    result = analyze_code("def broken(:\n    pass\n", "python")
    assert result.syntax_errors
    assert result.verification_status in {"REVIEW_REQUIRED", "MALICIOUS"}
    assert any("syntax" in flag for flag in result.anomaly_flags) or result.metrics["syntax_valid"] is False


def test_python_injection_patterns_still_score_high() -> None:
    result = analyze_code("def run(cmd):\n    eval(cmd)\n    os.system(cmd)\n", "python")
    assert result.threat_breakdown["injection_risk"] >= 48
    assert "injection:dynamic_execution" in result.anomaly_flags
    assert result.verification_status in {"MALICIOUS", "REVIEW_REQUIRED"}


def test_javascript_supported_sample_parses_cleanly() -> None:
    lexemes, errors = _javascript_lexemes(JS_SAMPLE)
    assert errors == []
    kinds = {lexeme.kind for lexeme in lexemes}
    assert "identifier" in kinds
    result = analyze_code(JS_SAMPLE, "javascript")
    assert result.language == "javascript"
    assert result.syntax_errors == []
    assert result.metrics["syntax_valid"] is True


def test_javascript_unterminated_string() -> None:
    lexemes, errors = _javascript_lexemes("const x = 'unterminated;")
    assert errors
    assert any("unterminated string" in item for item in errors)


def test_javascript_regex_literal_not_split_into_division() -> None:
    lexemes, errors = _javascript_lexemes("const pattern = /ab+c/i;\n")
    assert errors == []
    regex_tokens = [lexeme for lexeme in lexemes if lexeme.kind == "regex"]
    assert regex_tokens
    assert regex_tokens[0].value.startswith("/ab+c/")


def test_javascript_number_does_not_swallow_identifier() -> None:
    lexemes, errors = _javascript_lexemes("const n = 1.5;\nconst x = 0xFF;\n")
    assert errors == []
    numbers = [lexeme.value for lexeme in lexemes if lexeme.kind == "number"]
    assert "1.5" in numbers
    assert "0xFF" in numbers


def test_javascript_template_interpolation_inner_delimiters() -> None:
    source = "const msg = `hello ${foo(}`;"
    _lexemes, errors = _javascript_lexemes(source)
    assert any("unclosed delimiter" in item or "unexpected closing" in item or "unterminated" in item for item in errors)

    clean = "const msg = `hello ${name}`;"
    lexemes, errors = _javascript_lexemes(clean)
    assert errors == []
    assert any(lexeme.value == "${" for lexeme in lexemes)
    assert any(lexeme.kind == "identifier" and lexeme.value == "name" for lexeme in lexemes)


def test_inspect_code_http_python(client: TestClient) -> None:
    response = client.post("/api/v1/inspect-code", json={"language": "python", "source_code": PYTHON_SAMPLE})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification_status"] == "SECURE"
    assert body["language"] == "python"


def test_inspect_code_http_javascript(client: TestClient) -> None:
    response = client.post("/api/v1/inspect-code", json={"language": "javascript", "source_code": JS_SAMPLE})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["language"] == "javascript"
    assert body["syntax_errors"] == []


def test_inspect_code_code_alias(client: TestClient) -> None:
    response = client.post("/api/v1/inspect-code", json={"code": PYTHON_SAMPLE, "language": "python"})
    assert response.status_code == 200, response.text


def test_filter_threat_url_regression(client: TestClient) -> None:
    response = client.post(
        "/api/v1/filter-threat",
        json={"payload_type": "url", "url": "https://secure-login.example.top/verify?redirect=https%3A%2F%2Fevil.example"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["action"] in {"QUARANTINE", "BLOCK"}
    assert body["components"]["url_filter"]["indicators"]


def test_filter_threat_benign_code_allow_or_low_risk() -> None:
    result = run_threat_filter(ThreatFilterRequest(payload_type="code", source_code=PYTHON_SAMPLE, language="python"))
    assert result["action"] in {"ALLOW", "QUARANTINE"}
    assert result["components"]["code_analysis"]["verification_status"] == "SECURE"


def test_analyze_code_loader_does_not_use_wrong_main() -> None:
    analyze = ThreatFilterEngine._load_analyze_code()
    report = analyze("x = 1\n", "python")
    assert report.language == "python"
    assert report.syntax_errors == []


def test_code_engine_value_error_is_not_silently_quarantined() -> None:
    result = ThreatFilterEngine().filter_threat(
        ThreatFilterInput(payload_type="code", source_code="   \n", language="python")
    )
    assert result.action == "BLOCK"
    assert result.components["code_analysis"].get("error")
    assert result.components["code_analysis"]["hard_block"] is True


def test_frontend_file_limit_aligned_with_backend() -> None:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "app.js").read_text(encoding="utf-8")
    assert "Max 25 MB" in html
    assert "Max 250 MB" not in html
    assert "25 * 1024 * 1024" in javascript
    assert "250 * 1024 * 1024" not in javascript
    assert "250 MB evidence limit" not in javascript


def test_existing_xss_protections_preserved() -> None:
    javascript = (ROOT / "app.js").read_text(encoding="utf-8")
    assert "function escapeHtml" in javascript
    assert "replace(/[&<>'\"]/g" in javascript or "replace(/[&<>'\\\"]/g" in javascript
    for sink in ("alertTitle", "alertMessage", "alertEvidence", "previewName"):
        assert f"$('#{sink}').textContent" in javascript or f'$("#{sink}").textContent' in javascript
