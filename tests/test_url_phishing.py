"""Brand impersonation, hostname/port parsing, and malformed URL tests."""

from __future__ import annotations

from threat_filter_core import URLPhishingFilter, analyze_url, run_threat_filter, ThreatFilterRequest


def _indicators(url: str) -> set[str]:
    return set(URLPhishingFilter().inspect(url).indicators)


def test_brand_impersonation_hyphenated_domain() -> None:
    report = URLPhishingFilter().inspect("https://paypal-secure.tk/login")
    assert "lookalike_brand:paypal" in report.indicators
    assert report.normalized_host == "paypal-secure.tk"
    assert report.risk_score >= 19


def test_brand_impersonation_nested_brand_label() -> None:
    report = URLPhishingFilter().inspect("https://paypal.com.evil.top/verify")
    assert "lookalike_brand:paypal" in report.indicators
    assert "high_risk_tld" in report.indicators


def test_brand_impersonation_bait_prefix() -> None:
    report = URLPhishingFilter().inspect("https://securepaypal.support/signin")
    assert "lookalike_brand:paypal" in report.indicators


def test_brand_impersonation_microsoft_login_lookalike() -> None:
    report = URLPhishingFilter().inspect("https://login-microsoft.gq/account")
    assert "lookalike_brand:microsoft" in report.indicators


def test_legitimate_paypal_apex_not_flagged() -> None:
    report = URLPhishingFilter().inspect("https://paypal.com/signin")
    assert not any(item.startswith("lookalike_brand:") for item in report.indicators)
    assert report.normalized_host == "paypal.com"
    assert report.reputation_status == "NO_LOCAL_MATCH"


def test_legitimate_paypal_www_and_subdomain_not_flagged() -> None:
    for url in ("https://www.paypal.com/", "https://www.paypal.com/signin", "https://login.paypal.com/"):
        report = URLPhishingFilter().inspect(url)
        assert not any(item.startswith("lookalike_brand:") for item in report.indicators), url


def test_legitimate_google_api_host_not_flagged() -> None:
    report = URLPhishingFilter().inspect("https://www.googleapis.com/oauth2/v4/token")
    assert "lookalike_brand:google" not in report.indicators


def test_legitimate_github_usercontent_not_flagged() -> None:
    report = URLPhishingFilter().inspect("https://raw.githubusercontent.com/org/repo/main/README.md")
    assert "lookalike_brand:github" not in report.indicators


def test_substring_false_positive_notpaypal() -> None:
    report = URLPhishingFilter().inspect("https://notpaypal.example/info")
    assert "lookalike_brand:paypal" not in report.indicators


def test_hostname_and_port_parsed_from_https_url() -> None:
    report = URLPhishingFilter().inspect("https://example.com:8080/path")
    assert report.normalized_host == "example.com"
    assert "non_standard_port" in report.indicators
    assert "missing_hostname" not in report.indicators


def test_standard_https_port_not_flagged() -> None:
    report = URLPhishingFilter().inspect("https://example.com:443/path")
    assert report.normalized_host == "example.com"
    assert "non_standard_port" not in report.indicators


def test_schemeless_host_port_url() -> None:
    report = URLPhishingFilter().inspect("example.com:8080/login")
    assert report.normalized_host == "example.com"
    assert "missing_hostname" not in report.indicators
    assert "missing_explicit_scheme" in report.indicators
    assert "non_standard_port" in report.indicators


def test_schemeless_brand_impersonation_with_port() -> None:
    """A port suffix must not hide brand impersonation on schemeless URLs."""

    report = URLPhishingFilter().inspect("paypal-login.example.top:8443/verify")
    assert report.normalized_host == "paypal-login.example.top"
    assert "lookalike_brand:paypal" in report.indicators
    assert "non_standard_port" in report.indicators
    assert "missing_hostname" not in report.indicators


def test_protocol_relative_url() -> None:
    report = URLPhishingFilter().inspect("//cdn.example.com/assets/app.js")
    assert report.normalized_host == "cdn.example.com"
    assert "missing_explicit_scheme" in report.indicators


def test_javascript_scheme_still_hard_blocks() -> None:
    report = URLPhishingFilter().inspect("javascript:alert(1)")
    assert report.hard_block is True
    assert "non_web_scheme" in report.indicators or "javascript_scheme" in report.indicators


def test_malformed_empty_url_rejected() -> None:
    try:
        URLPhishingFilter().inspect("   ")
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("expected ValueError for empty URL")


def test_malformed_missing_host() -> None:
    report = URLPhishingFilter().inspect("http://")
    assert "missing_hostname" in report.indicators
    assert report.risk_score >= 40


def test_malformed_invalid_port_fail_closed() -> None:
    try:
        URLPhishingFilter().inspect("https://example.com:99999/login")
    except ValueError as exc:
        assert "cannot be parsed safely" in str(exc)
    else:
        raise AssertionError("expected ValueError for an invalid port")


def test_pipeline_blocks_malformed_url() -> None:
    result = run_threat_filter(ThreatFilterRequest(payload_type="url", url="https://example.com:99999/login"))
    assert result["action"] == "BLOCK"
    assert result["components"]["url_filter"]["error"]


def test_analyze_url_convenience_wrapper() -> None:
    payload = analyze_url("https://github.com/veritas/inspector")
    assert payload["normalized_host"] == "github.com"
    assert "lookalike_brand:github" not in payload["indicators"]


def test_ipv6_literal_with_port() -> None:
    report = URLPhishingFilter().inspect("https://[2001:db8::1]:8080/health")
    assert "2001:db8::1" in report.normalized_host
    assert "ip_literal_hostname" in report.indicators
    assert "non_standard_port" in report.indicators
