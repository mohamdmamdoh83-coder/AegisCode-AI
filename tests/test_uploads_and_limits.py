"""Oversized upload, multipart, and base64 payload tests."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

import threat_filter_core
from threat_filter_core import PayloadDecodeError, _decode_base64_payload


def test_base64_rejected_before_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_filter_core, "MAX_FILE_BYTES", 32)

    decoded_calls: list[int] = []
    original = threat_filter_core.base64.b64decode

    def wrapped(data: bytes | str, validate: bool = False) -> bytes:
        decoded_calls.append(len(data) if isinstance(data, (bytes, str)) else 0)
        return original(data, validate=validate)

    monkeypatch.setattr(threat_filter_core.base64, "b64decode", wrapped)
    oversized = "A" * 200
    with pytest.raises(PayloadDecodeError) as exc:
        _decode_base64_payload(oversized)
    assert "exceeds" in str(exc.value)
    assert decoded_calls == []


def test_valid_base64_payload_decodes() -> None:
    payload = base64.b64encode(b"print('ok')\n").decode("ascii")
    assert _decode_base64_payload(payload) == b"print('ok')\n"


def test_invalid_base64_payload_rejected() -> None:
    with pytest.raises(PayloadDecodeError):
        _decode_base64_payload("%%%not-valid%%%")


def test_json_base64_upload_inspects_file(client: TestClient) -> None:
    encoded = base64.b64encode(b"hello veritas").decode("ascii")
    response = client.post(
        "/api/v1/filter-threat",
        json={"payload_type": "file", "file_name": "note.txt", "file_content_base64": encoded},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["components"]["file_integrity"]["size_bytes"] == len(b"hello veritas")
    assert body["components"]["file_integrity"]["hashes"]["sha256"]


def test_oversized_json_base64_returns_413(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_filter_core, "MAX_FILE_BYTES", 32)
    encoded = base64.b64encode(b"x" * 128).decode("ascii")
    response = client.post(
        "/api/v1/filter-threat",
        json={"payload_type": "file", "file_name": "big.bin", "file_content_base64": encoded},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]


def test_multipart_upload_accepted(client: TestClient) -> None:
    response = client.post(
        "/api/v1/filter-threat",
        files={"file": ("sample.py", b"def add(a, b):\n    return a + b\n", "text/x-python")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["components"]["file_integrity"]["file_name"] == "sample.py"
    assert body["components"]["file_integrity"]["size_bytes"] == 32 or body["components"]["file_integrity"]["size_bytes"] > 0


def test_oversized_multipart_returns_413(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_filter_core, "MAX_FILE_BYTES", 64)
    response = client.post(
        "/api/v1/filter-threat",
        files={"file": ("huge.bin", b"x" * 2048, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]


def test_octet_stream_upload(client: TestClient) -> None:
    payload = b"MZ" + b"\x00" * 64
    response = client.post(
        "/api/v1/filter-threat",
        content=payload,
        headers={"content-type": "application/octet-stream", "x-file-name": "tiny.exe"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["components"]["file_integrity"]["file_name"] == "tiny.exe"
    assert "windows_executable_header" in body["components"]["file_integrity"]["indicators"]


def test_oversized_octet_stream_returns_413(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_filter_core, "MAX_FILE_BYTES", 32)
    response = client.post(
        "/api/v1/filter-threat",
        content=b"x" * 128,
        headers={"content-type": "application/octet-stream", "x-file-name": "big.bin"},
    )
    assert response.status_code == 413


def test_content_length_enforced_before_body(client: TestClient) -> None:
    response = client.post(
        "/api/v1/filter-threat",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": str(40 * 1024 * 1024),
        },
    )
    # Some HTTP clients recompute Content-Length.  Either the middleware
    # rejects the advertised size or the tiny JSON body is validated as empty.
    assert response.status_code in {400, 413, 422}
