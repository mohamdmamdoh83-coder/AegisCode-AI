"""Threat filtering and endpoint-protection core for Veritas Inspector.

The module is intentionally usable in two ways:

* imported by ``backend_core.py`` to add ``POST /api/v1/filter-threat`` to the
  existing analysis service; or
* run directly with ``python threat_filter_core.py`` to serve the threat-filter
  API as a small standalone service.

It does not execute submitted files, contact external reputation services, or
inspect the host operating system. File and process inspection are safe,
read-only simulations over caller-provided bytes and process snapshots. The
scoring pipeline is deterministic for the same inputs, while the response also
contains forensic logs suitable for an analyst or a quarantine queue.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit

import numpy as np
from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_TEXT_CHARS = 200_000
MAX_URL_CHARS = 8_192

ALLOW = "ALLOW"
QUARANTINE = "QUARANTINE"
BLOCK = "BLOCK"


class PayloadDecodeError(ValueError):
    """Raised when a submitted base64 file payload cannot be decoded safely."""


@dataclass(slots=True)
class ForensicLog:
    """A structured, JSON-friendly security event."""

    sequence: int
    stage: str
    level: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FileIntegrityReport:
    file_name: str
    size_bytes: int
    risk_score: float
    hard_block: bool
    integrity_status: str
    hashes: dict[str, str]
    metadata: dict[str, Any]
    threat_breakdown: dict[str, float]
    indicators: list[str]
    forensic_logs: list[ForensicLog]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["forensic_logs"] = [entry.to_dict() for entry in self.forensic_logs]
        return result


@dataclass(slots=True)
class URLThreatReport:
    url_hash: str
    normalized_host: str
    risk_score: float
    hard_block: bool
    reputation_status: str
    metadata: dict[str, Any]
    threat_breakdown: dict[str, float]
    indicators: list[str]
    forensic_logs: list[ForensicLog]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["forensic_logs"] = [entry.to_dict() for entry in self.forensic_logs]
        return result


@dataclass(slots=True)
class ProcessSnapshotReport:
    pid: Optional[int]
    name: str
    risk_score: float
    hard_block: bool
    indicators: list[str]
    metadata: dict[str, Any]
    forensic_logs: list[ForensicLog]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["forensic_logs"] = [entry.to_dict() for entry in self.forensic_logs]
        return result


@dataclass(slots=True)
class ProcessThreatReport:
    threat_level_index: float
    threat_level: str
    hard_block: bool
    process_count: int
    anomalous_process_count: int
    processes: list[ProcessSnapshotReport]
    threat_breakdown: dict[str, float]
    forensic_logs: list[ForensicLog]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["processes"] = [process.to_dict() for process in self.processes]
        result["forensic_logs"] = [entry.to_dict() for entry in self.forensic_logs]
        return result


@dataclass(slots=True)
class ThreatFilterInput:
    """Normalized multi-type input consumed by :class:`ThreatFilterEngine`."""

    payload_type: str = "auto"
    file_name: Optional[str] = None
    file_bytes: Optional[bytes] = None
    declared_sha256: Optional[str] = None
    allowed_sha256: Sequence[str] = field(default_factory=tuple)
    blocked_sha256: Sequence[str] = field(default_factory=tuple)
    source_code: Optional[str] = None
    language: str = "auto"
    url: Optional[str] = None
    network_payload: Optional[str] = None
    processes: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ThreatFilterResult:
    analysis_id: str
    analyzed_at: str
    action: str
    threat_level_index: float
    confidence_index: float
    summary: str
    threat_breakdown: dict[str, float]
    components: dict[str, Any]
    forensic_logs: list[ForensicLog]
    policy_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["forensic_logs"] = [entry.to_dict() for entry in self.forensic_logs]
        return result


# ---------------------------------------------------------------------------
# Shared numerical, hashing, and evidence helpers
# ---------------------------------------------------------------------------


def _clip(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return float(np.clip(float(value), low, high))


def _round(value: float, digits: int = 2) -> float:
    return round(float(value), digits)


def _entropy_bytes(data: bytes) -> float:
    """Calculate byte entropy normalized to a 0-100 percentage."""

    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    probabilities = counts[counts > 0] / float(len(data))
    entropy_bits = -float(np.sum(probabilities * np.log2(probabilities)))
    return _clip((entropy_bits / 8.0) * 100.0)


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _log(
    sequence: int,
    stage: str,
    level: str,
    message: str,
    **evidence: Any,
) -> ForensicLog:
    return ForensicLog(sequence, stage, level, message, evidence)


def _next_sequence(logs: list[ForensicLog]) -> int:
    return len(logs) + 1


def _action_for_risk(risk_score: float, hard_block: bool = False) -> str:
    if hard_block or risk_score >= 75.0:
        return BLOCK
    if risk_score >= 40.0:
        return QUARANTINE
    return ALLOW


def _normalize_hashes(values: Sequence[str]) -> set[str]:
    return {str(value).strip().lower() for value in values if value and str(value).strip()}


def _decode_base64_payload(value: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise PayloadDecodeError("file_content_base64 must be a non-empty base64 string")
    compact = re.sub(r"\s+", "", value)
    # Padding is added only when the length is otherwise valid for base64. The
    # strict decoder still rejects arbitrary non-alphabet characters.
    compact += "=" * (-len(compact) % 4)
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PayloadDecodeError("file_content_base64 is not valid base64") from exc
    if len(data) > MAX_FILE_BYTES:
        raise PayloadDecodeError(f"decoded file exceeds the {MAX_FILE_BYTES:,}-byte limit")
    return data


# ---------------------------------------------------------------------------
# 1. File and binary integrity scanner
# ---------------------------------------------------------------------------


_SCRIPT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".ts",
    ".tsx",
    ".sh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".php",
    ".rb",
    ".pl",
}
_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".msi", ".com", ".bin", ".dylib", ".so"}
_SCRIPT_THREAT_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("dynamic_execution", re.compile(r"\b(?:eval|exec|compile|Function)\s*\(", re.I), 27.0),
    ("encoded_decoder", re.compile(r"\b(?:atob|btoa|base64\.(?:b64)?decode|fromCharCode|unescape)\b", re.I), 23.0),
    ("process_spawn", re.compile(r"\b(?:subprocess|child_process|os\.system|powershell|cmd\.exe)\b", re.I), 27.0),
    ("credential_access", re.compile(r"\b(?:document\.cookie|localStorage|sessionStorage|password|credential)\b", re.I), 21.0),
    ("html_injection", re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", re.I), 18.0),
    ("destructive_command", re.compile(r"(?:rm\s+-rf|curl\s+[^\n]+\|\s*(?:sh|bash)|wget\s+[^\n]+\|\s*(?:sh|bash))", re.I), 35.0),
)
_BASE64_LITERAL_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
_ESCAPE_PAYLOAD_RE = re.compile(r"(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){3,}", re.I)


class FileIntegrityScanner:
    """Read-only hash, metadata, binary-header, and script-structure scanner."""

    def scan(
        self,
        file_name: str,
        file_bytes: bytes,
        *,
        declared_sha256: Optional[str] = None,
        allowed_sha256: Sequence[str] = (),
        blocked_sha256: Sequence[str] = (),
        claimed_mime: Optional[str] = None,
    ) -> FileIntegrityReport:
        logs: list[ForensicLog] = []
        if not isinstance(file_bytes, bytes):
            raise TypeError("file_bytes must be bytes")
        if len(file_bytes) > MAX_FILE_BYTES:
            raise ValueError(f"file exceeds the {MAX_FILE_BYTES:,}-byte limit")
        if not file_name or not isinstance(file_name, str):
            file_name = "unnamed-payload"

        file_hashes = _hashes(file_bytes)
        sha256 = file_hashes["sha256"]
        normalized_name = os.path.basename(file_name).strip() or "unnamed-payload"
        extension = os.path.splitext(normalized_name.lower())[1]
        magic, header_metadata, magic_risk, magic_flags = self._binary_header(file_bytes)
        text, text_decodable = self._decode_text(file_bytes)
        script_metadata, script_risk, script_flags = self._script_structure(text, extension, text_decodable)
        byte_entropy = _entropy_bytes(file_bytes)
        printable_ratio = self._printable_ratio(file_bytes)
        hash_allowlist = _normalize_hashes(allowed_sha256)
        hash_blocklist = _normalize_hashes(blocked_sha256)

        indicators: list[str] = []
        risk = 0.0
        hard_block = False
        integrity_status = "UNTRUSTED_PAYLOAD"

        if sha256 in hash_blocklist:
            risk = 100.0
            hard_block = True
            integrity_status = "BLOCKED_HASH_MATCH"
            indicators.append("blocked_sha256_match")
            logs.append(_log(_next_sequence(logs), "hash", "critical", "SHA-256 matched the supplied blocklist.", sha256=sha256))
        elif sha256 in hash_allowlist:
            integrity_status = "ALLOWLIST_MATCH"
            risk = max(0.0, risk - 30.0)
            indicators.append("allowlist_sha256_match")
            logs.append(_log(_next_sequence(logs), "hash", "info", "SHA-256 matched the supplied allowlist.", sha256=sha256))
        else:
            logs.append(_log(_next_sequence(logs), "hash", "info", "Cryptographic fingerprints calculated.", sha256=sha256, size_bytes=len(file_bytes)))

        if declared_sha256:
            declared = declared_sha256.strip().lower()
            if declared != sha256:
                risk += 48.0
                indicators.append("declared_hash_mismatch")
                logs.append(_log(_next_sequence(logs), "integrity", "high", "Declared SHA-256 does not match the received bytes.", declared_sha256=declared, actual_sha256=sha256))
            else:
                logs.append(_log(_next_sequence(logs), "integrity", "info", "Declared SHA-256 matches received bytes."))

        path_like_name = file_name.replace("\\", "/")
        if ".." in path_like_name.split("/") or path_like_name.startswith(("/", "\\")):
            risk += 24.0
            indicators.append("path_traversal_filename")
            logs.append(_log(_next_sequence(logs), "metadata", "high", "Filename contains an absolute or traversal path."))

        if extension in _EXECUTABLE_EXTENSIONS:
            risk += 16.0
            indicators.append("executable_extension")
        if magic in {"PE", "PE/DOS", "ELF", "Mach-O"} and sha256 not in hash_allowlist and sha256 not in hash_blocklist:
            # Unknown native binaries are held for review by default. The
            # allowlist is explicit so a signed/approved agent can opt out.
            risk += 15.0
            indicators.append("unallowlisted_native_executable")
            logs.append(_log(_next_sequence(logs), "integrity", "medium", "Native executable is not present in the supplied allowlist."))
        if len(re.findall(r"\.[A-Za-z0-9]{1,8}", normalized_name)) >= 2:
            risk += 16.0
            indicators.append("double_extension")
        if byte_entropy >= 91.0 and len(file_bytes) >= 512:
            risk += 18.0
            indicators.append("high_entropy_binary")
            logs.append(_log(_next_sequence(logs), "entropy", "medium", "Byte entropy is consistent with compression, packing, or encryption.", entropy_index=_round(byte_entropy)))

        risk += magic_risk
        indicators.extend(magic_flags)
        risk += script_risk
        indicators.extend(f"script:{flag}" for flag in script_flags)

        if claimed_mime:
            guessed_mime = mimetypes.guess_type(normalized_name)[0]
            if guessed_mime and claimed_mime.lower() != guessed_mime.lower():
                risk += 10.0
                indicators.append("claimed_mime_mismatch")

        risk = _clip(risk)
        if hard_block:
            risk = 100.0
        elif risk >= 75.0:
            hard_block = bool("blocked_sha256_match" in indicators or "destructive_command" in script_flags)

        metadata: dict[str, Any] = {
            "extension": extension or None,
            "mime_guess": mimetypes.guess_type(normalized_name)[0],
            "magic_type": magic,
            "byte_entropy_index": _round(byte_entropy),
            "printable_ratio": _round(printable_ratio),
            "is_probably_text": bool(text_decodable and printable_ratio >= 0.55),
            "header": header_metadata,
            "script": script_metadata,
        }
        logs.append(_log(_next_sequence(logs), "metadata", "info", "File metadata and header structure inspected.", magic_type=magic, extension=extension or None))
        if script_flags:
            logs.append(_log(_next_sequence(logs), "script", "high" if script_risk >= 45 else "medium", "Script structure contains suspicious execution or encoding signals.", indicators=script_flags))
        if magic_flags:
            logs.append(_log(_next_sequence(logs), "binary", "high" if magic_risk >= 30 else "medium", "Binary header inspection produced anomaly signals.", indicators=magic_flags))

        threat_breakdown = {
            "hash_reputation_risk": 100.0 if "blocked_sha256_match" in indicators else (0.0 if "allowlist_sha256_match" in indicators else 12.0),
            "binary_header_risk": _round(_clip(magic_risk * 2.0)),
            "metadata_risk": _round(_clip((24.0 if "path_traversal_filename" in indicators else 0.0) + (16.0 if "double_extension" in indicators else 0.0))),
            "script_structure_risk": _round(_clip(script_risk)),
            "entropy_risk": _round(_clip(max(0.0, (byte_entropy - 70.0) * 3.33))),
        }
        logs.append(_log(_next_sequence(logs), "verdict", "critical" if hard_block else ("high" if risk >= 75 else "info"), f"File integrity risk scored at {risk:.2f}/100."))
        return FileIntegrityReport(
            file_name=normalized_name,
            size_bytes=len(file_bytes),
            risk_score=_round(risk),
            hard_block=hard_block,
            integrity_status=integrity_status,
            hashes=file_hashes,
            metadata=metadata,
            threat_breakdown=threat_breakdown,
            indicators=sorted(set(indicators)),
            forensic_logs=logs,
        )

    @staticmethod
    def _printable_ratio(file_bytes: bytes) -> float:
        if not file_bytes:
            return 1.0
        printable = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in file_bytes)
        return printable / len(file_bytes)

    @staticmethod
    def _decode_text(file_bytes: bytes) -> tuple[str, bool]:
        if not file_bytes:
            return "", True
        try:
            return file_bytes.decode("utf-8"), True
        except UnicodeDecodeError:
            return file_bytes.decode("utf-8", errors="replace"), False

    @staticmethod
    def _binary_header(file_bytes: bytes) -> tuple[str, dict[str, Any], float, list[str]]:
        """Inspect common PE/ELF/Mach-O headers without executing anything."""

        if file_bytes.startswith(b"MZ"):
            metadata: dict[str, Any] = {"format": "PE/DOS", "valid_pe_signature": False}
            flags = ["windows_executable_header"]
            risk = 28.0
            if len(file_bytes) >= 0x40:
                pe_offset = int.from_bytes(file_bytes[0x3C:0x40], "little", signed=False)
                metadata["pe_header_offset"] = pe_offset
                if pe_offset + 24 <= len(file_bytes) and file_bytes[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    metadata["format"] = "PE"
                    metadata["valid_pe_signature"] = True
                    metadata["machine"] = f"0x{int.from_bytes(file_bytes[pe_offset + 4 : pe_offset + 6], 'little'):04x}"
                    metadata["section_count"] = int.from_bytes(file_bytes[pe_offset + 6 : pe_offset + 8], "little")
                    risk = 23.0
                    flags.append("pe_header_present")
                else:
                    risk += 22.0
                    flags.append("invalid_pe_offset_or_signature")
            else:
                risk += 22.0
                flags.append("truncated_pe_header")
            return metadata["format"], metadata, risk, flags

        if file_bytes.startswith(b"\x7fELF"):
            metadata = {
                "format": "ELF",
                "class": "64-bit" if len(file_bytes) > 4 and file_bytes[4] == 2 else "32-bit" if len(file_bytes) > 4 and file_bytes[4] == 1 else "unknown",
                "endianness": "little" if len(file_bytes) > 5 and file_bytes[5] == 1 else "big" if len(file_bytes) > 5 and file_bytes[5] == 2 else "unknown",
            }
            return "ELF", metadata, 27.0, ["unix_executable_header"]

        if len(file_bytes) >= 4 and file_bytes[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
            return "Mach-O", {"format": "Mach-O", "fat_or_64_bit": file_bytes[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}}, 27.0, ["macos_executable_header"]
        if file_bytes.startswith(b"#!"):
            first_line = file_bytes.splitlines()[0][:180].decode("utf-8", errors="replace")
            return "Script", {"format": "script", "shebang": first_line}, 7.0, ["script_shebang"]
        if file_bytes.startswith(b"PK\x03\x04"):
            return "ZIP/container", {"format": "zip"}, 8.0, ["compressed_container"]
        if file_bytes.startswith(b"%PDF"):
            return "PDF", {"format": "pdf"}, 7.0, ["document_container"]
        return "Unknown", {"format": "unknown"}, 0.0, []

    @staticmethod
    def _script_structure(text: str, extension: str, decodable: bool) -> tuple[dict[str, Any], float, list[str]]:
        script_marker = re.search(r"(?:^#!|\b(?:def|class|function|const|let|var|import|#!/|powershell)\b|<\?(?:php)?)", text, re.I | re.M)
        if not text or (extension not in _SCRIPT_EXTENSIONS and script_marker is None):
            return {"detected": False}, 0.0, []

        flags: list[str] = []
        risk = 0.0
        matches: list[str] = []
        for name, pattern, weight in _SCRIPT_THREAT_PATTERNS:
            if pattern.search(text):
                flags.append(name)
                matches.append(name)
                risk += weight
        base64_literals = len(_BASE64_LITERAL_RE.findall(text))
        escaped_payloads = len(_ESCAPE_PAYLOAD_RE.findall(text))
        longest_line = max((len(line) for line in text.splitlines()), default=0)
        if base64_literals:
            risk += min(30.0, base64_literals * 18.0)
            flags.append("opaque_base64_literal")
        if escaped_payloads:
            risk += min(25.0, escaped_payloads * 15.0)
            flags.append("escaped_payload")
        if longest_line >= 300:
            risk += 16.0
            flags.append("packed_long_line")
        if len(matches) > 1:
            risk += min(18.0, (len(matches) - 1) * 5.0)
        if not decodable:
            risk += 12.0
            flags.append("non_utf8_script_bytes")
        metadata = {
            "detected": True,
            "line_count": max(1, text.count("\n") + 1),
            "character_count": len(text),
            "longest_line": longest_line,
            "base64_literal_count": base64_literals,
            "escaped_payload_count": escaped_payloads,
        }
        return metadata, _clip(risk), flags


# ---------------------------------------------------------------------------
# 2. URL and web-traffic phishing filter
# ---------------------------------------------------------------------------


_URL_SIGNATURES: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("javascript_scheme", re.compile(r"^\s*(?:javascript|vbscript|data):", re.I), 65.0),
    ("script_injection", re.compile(r"<\s*script|on(?:error|load|click)\s*=|javascript%3a", re.I), 45.0),
    ("sql_injection", re.compile(r"(?:union\s+select|or\s+1\s*=\s*1|sleep\s*\(|information_schema|;\s*drop\s+table)", re.I), 47.0),
    ("path_traversal", re.compile(r"(?:\.\./|%2e%2e%2f|%252e%252e)", re.I), 34.0),
    ("shell_injection", re.compile(r"(?:[;&|`]\s*(?:cat|curl|wget|bash|sh|powershell)|\$\([^)]*\)|%24%28)", re.I), 45.0),
    ("jndi_or_template_injection", re.compile(r"(?:\$\{jndi:|\{\{.*(?:constructor|__proto__)|\$\{.*(?:process|child_process))", re.I), 55.0),
    ("encoded_redirect", re.compile(r"(?:%2f%2f|%3a%2f%2f|https?%3a%2f%2f)", re.I), 22.0),
)
_REDIRECT_KEYS = {"url", "uri", "redirect", "redirect_uri", "next", "return", "returnto", "continue", "dest", "destination", "target", "to"}
_SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "gq", "tk", "work", "support", "country", "fit"}
_BRAND_MARKERS = {"paypal", "microsoft", "google", "apple", "github", "amazon", "linkedin", "docusign"}


class URLPhishingFilter:
    """Local-only URL and network-payload heuristic filter."""

    def inspect(self, url: str, network_payload: Optional[str] = None) -> URLThreatReport:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("url must be a non-empty string")
        if len(url) > MAX_URL_CHARS:
            raise ValueError(f"url exceeds the {MAX_URL_CHARS:,}-character limit")

        raw_url = url.strip()
        logs: list[ForensicLog] = []
        indicators: list[str] = []
        risk = 0.0
        hard_block = False
        scheme_input = raw_url.split(":", 1)[0].lower() if ":" in raw_url else ""
        parse_target = raw_url if scheme_input else f"https://{raw_url}"

        try:
            parts = urlsplit(parse_target)
            host = (parts.hostname or "").strip(".").lower()
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"url cannot be parsed safely: {exc}") from exc

        if not host:
            risk += 42.0
            indicators.append("missing_hostname")
            logs.append(_log(_next_sequence(logs), "url", "high", "URL does not contain a resolvable hostname."))
        normalized_host = host
        if any(ord(character) > 127 for character in host):
            indicators.append("unicode_hostname")
            risk += 18.0
            try:
                normalized_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                normalized_host = host
        if "xn--" in normalized_host:
            indicators.append("punycode_hostname")
            risk += 22.0
        try:
            ipaddress.ip_address(host)
            indicators.append("ip_literal_hostname")
            risk += 25.0
        except ValueError:
            pass

        if scheme_input and scheme_input not in {"http", "https"}:
            indicators.append("non_web_scheme")
            risk += 55.0
            hard_block = scheme_input in {"javascript", "vbscript", "data", "file"}
        elif not scheme_input:
            indicators.append("missing_explicit_scheme")
            risk += 5.0
        if scheme_input == "http":
            indicators.append("unencrypted_http")
            risk += 10.0
        if "@" in parts.netloc:
            indicators.append("userinfo_obfuscation")
            risk += 23.0
        if port and port not in {80, 443}:
            indicators.append("non_standard_port")
            risk += 12.0
        if len(normalized_host) > 63:
            indicators.append("long_hostname")
            risk += 14.0
        labels = [label for label in normalized_host.split(".") if label]
        if len(labels) >= 5:
            indicators.append("excessive_subdomains")
            risk += 18.0
        if any(label.startswith("-") or label.endswith("-") for label in labels):
            indicators.append("invalid_label_hyphen")
            risk += 15.0
        if labels and labels[-1] in _SUSPICIOUS_TLDS:
            indicators.append("high_risk_tld")
            risk += 14.0

        host_without_port = normalized_host.split(":", 1)[0]
        for brand in _BRAND_MARKERS:
            if brand in host_without_port and not host_without_port.endswith(f"{brand}.com") and not host_without_port == f"www.{brand}.com":
                indicators.append(f"lookalike_brand:{brand}")
                risk += 19.0

        decoded_url = unquote(raw_url)
        for name, pattern, weight in _URL_SIGNATURES:
            if pattern.search(decoded_url):
                indicators.append(name)
                risk += weight
                if name in {"javascript_scheme", "jndi_or_template_injection", "shell_injection"}:
                    hard_block = True

        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        redirect_count = 0
        external_redirect = False
        for key, value in query_pairs:
            if key.lower() in _REDIRECT_KEYS:
                redirect_count += 1
                try:
                    redirect_host = (urlsplit(value).hostname or "").lower()
                    if redirect_host and redirect_host != host and not redirect_host.endswith(f".{host}"):
                        external_redirect = True
                except ValueError:
                    external_redirect = True
        if redirect_count:
            indicators.append("redirect_parameter")
            risk += min(22.0, redirect_count * 11.0)
        if external_redirect:
            indicators.append("external_redirect_target")
            risk += 24.0

        payload_risk = 0.0
        payload_flags: list[str] = []
        if network_payload:
            payload_text = network_payload if isinstance(network_payload, str) else str(network_payload)
            for name, pattern, weight in _URL_SIGNATURES:
                if pattern.search(unquote(payload_text)):
                    payload_flags.append(f"payload:{name}")
                    payload_risk += weight * 0.75
            if len(payload_text) > 100_000:
                payload_flags.append("oversized_network_payload")
                payload_risk += 20.0
            indicators.extend(payload_flags)
            risk += payload_risk
            logs.append(_log(_next_sequence(logs), "payload", "high" if payload_risk >= 40 else "medium", "Network payload signatures evaluated.", payload_length=len(payload_text), matched=payload_flags))

        risk = _clip(risk)
        if risk >= 75.0:
            hard_block = hard_block or bool(payload_flags)
        reputation_status = "HIGH_RISK" if risk >= 75 else "SUSPICIOUS" if risk >= 40 else "NO_LOCAL_MATCH"
        threat_breakdown = {
            "scheme_risk": _round(min(100.0, 65.0 if "non_web_scheme" in indicators else (10.0 if "unencrypted_http" in indicators else 0.0))),
            "domain_anomaly_risk": _round(_clip(risk * 0.42)),
            "redirect_risk": _round(_clip((24.0 if "external_redirect_target" in indicators else 0.0) + (22.0 if "redirect_parameter" in indicators else 0.0))),
            "signature_risk": _round(_clip(risk * 0.7 if any(item in indicators for item in ("script_injection", "sql_injection", "shell_injection", "jndi_or_template_injection")) else 0.0)),
            "network_payload_risk": _round(_clip(payload_risk)),
        }
        logs.append(_log(_next_sequence(logs), "url", "critical" if hard_block else ("high" if risk >= 75 else "info"), "URL normalized and heuristic reputation scored.", host=normalized_host, risk_score=_round(risk)))
        if indicators:
            logs.append(_log(_next_sequence(logs), "indicators", "high" if risk >= 60 else "medium", "URL anomaly indicators recorded.", indicators=sorted(set(indicators))))
        return URLThreatReport(
            url_hash=_hash_text(raw_url),
            normalized_host=normalized_host,
            risk_score=_round(risk),
            hard_block=hard_block,
            reputation_status=reputation_status,
            metadata={
                "scheme": scheme_input or "https-assumed",
                "path_length": len(parts.path),
                "query_parameter_count": len(query_pairs),
                "redirect_parameter_count": redirect_count,
                "network_payload_inspected": bool(network_payload),
            },
            threat_breakdown=threat_breakdown,
            indicators=sorted(set(indicators)),
            forensic_logs=logs,
        )


# ---------------------------------------------------------------------------
# 3. Simulated system process anomaly detector
# ---------------------------------------------------------------------------


_MEMORY_INJECTION_TAGS = {
    "remote_thread",
    "createremotethread",
    "create_remote_thread",
    "write_process_memory",
    "virtualalloc",
    "virtual_alloc_ex",
    "process_hollowing",
    "dll_injection",
    "manual_map",
    "ptrace",
    "reflective_loader",
}
_SUSPICIOUS_PROCESS_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("encoded_powershell", re.compile(r"powershell(?:\.exe)?[^\n]*(?:\s-enc(?:odedcommand)?\s|frombase64string)", re.I), 46.0),
    ("living_off_land_binary", re.compile(r"\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|wmic)\b", re.I), 34.0),
    ("shell_download_pipe", re.compile(r"(?:curl|wget)\s+[^\n]+\|\s*(?:sh|bash|powershell)", re.I), 48.0),
    ("suspicious_temp_execution", re.compile(r"(?:\\temp\\|/tmp/|/var/tmp/|appdata\\local\\temp)", re.I), 22.0),
    ("credential_or_browser_target", re.compile(r"(?:lsass|sam\b|browser\s+(?:cookie|credential)|chrom(e|ium).*(?:cookie|login))", re.I), 42.0),
)
_SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "pdfreader.exe"}


class ProcessAnomalyDetector:
    """Analyze caller-provided process snapshots without touching the host OS."""

    def analyze(self, processes: Sequence[Mapping[str, Any]]) -> ProcessThreatReport:
        logs: list[ForensicLog] = []
        reports: list[ProcessSnapshotReport] = []
        if not processes:
            logs.append(_log(1, "process", "info", "No process snapshot supplied; idle protection baseline is 0.00."))
            return ProcessThreatReport(0.0, "NORMAL", False, 0, 0, [], {"memory_injection_risk": 0.0, "command_line_risk": 0.0, "identity_risk": 0.0, "resource_risk": 0.0}, logs)

        for index, process in enumerate(processes, start=1):
            report = self._inspect_process(process, index)
            reports.append(report)
            logs.extend(report.forensic_logs)

        risk_values = np.asarray([report.risk_score for report in reports], dtype=np.float64)
        maximum = float(np.max(risk_values)) if len(risk_values) else 0.0
        average = float(np.mean(risk_values)) if len(risk_values) else 0.0
        upper_percentile = float(np.percentile(risk_values, 90)) if len(risk_values) else 0.0
        threat_index = _clip(0.55 * maximum + 0.25 * upper_percentile + 0.20 * average)
        hard_block = any(report.hard_block for report in reports)
        level = "CRITICAL" if threat_index >= 75 else "ELEVATED" if threat_index >= 40 else "NORMAL"
        anomalous_count = sum(report.risk_score >= 40 for report in reports)
        breakdown = {
            "memory_injection_risk": _round(max((self._breakdown_value(report, "memory_injection_risk") for report in reports), default=0.0)),
            "command_line_risk": _round(max((self._breakdown_value(report, "command_line_risk") for report in reports), default=0.0)),
            "identity_risk": _round(max((self._breakdown_value(report, "identity_risk") for report in reports), default=0.0)),
            "resource_risk": _round(max((self._breakdown_value(report, "resource_risk") for report in reports), default=0.0)),
        }
        logs.append(_log(len(logs) + 1, "process", "critical" if hard_block else ("high" if threat_index >= 75 else "info"), "Process behavior snapshot aggregated into a real-time threat index.", threat_level_index=_round(threat_index), process_count=len(reports), anomalous_process_count=anomalous_count))
        return ProcessThreatReport(_round(threat_index), level, hard_block, len(reports), anomalous_count, reports, breakdown, logs)

    def _inspect_process(self, process: Mapping[str, Any], sequence: int) -> ProcessSnapshotReport:
        if not isinstance(process, Mapping):
            process = {}
        logs: list[ForensicLog] = []
        name = str(process.get("name") or "unknown-process")[:160]
        pid_value = process.get("pid")
        try:
            pid: Optional[int] = int(pid_value) if pid_value is not None else None
        except (TypeError, ValueError):
            pid = None
        command_line = str(process.get("command_line") or process.get("cmdline") or "")
        parent_name = str(process.get("parent_name") or process.get("parent") or "").lower()
        behavior_values = process.get("behavior_tags") or process.get("behavior_signatures") or []
        if isinstance(behavior_values, str):
            behavior_values = [behavior_values]
        behavior_tags = {str(value).lower().replace("-", "_").replace(" ", "_") for value in behavior_values}
        indicators: list[str] = []
        risk = 0.0
        hard_block = False
        breakdown = {"memory_injection_risk": 0.0, "command_line_risk": 0.0, "identity_risk": 0.0, "resource_risk": 0.0}

        injection_hits = sorted(behavior_tags.intersection(_MEMORY_INJECTION_TAGS))
        if injection_hits:
            injection_risk = min(100.0, 48.0 + len(injection_hits) * 17.0)
            breakdown["memory_injection_risk"] = injection_risk
            risk += injection_risk
            indicators.extend(f"memory_injection:{item}" for item in injection_hits)
            hard_block = len(injection_hits) >= 2 or not bool(process.get("signed", False))
            logs.append(_log(sequence, "memory", "critical" if hard_block else "high", "Unauthorized memory-injection behavior signature detected.", tags=injection_hits))

        command_risk = 0.0
        for indicator, pattern, weight in _SUSPICIOUS_PROCESS_PATTERNS:
            if pattern.search(command_line):
                indicators.append(indicator)
                command_risk += weight
        if command_risk:
            breakdown["command_line_risk"] = _clip(command_risk)
            risk += command_risk
            logs.append(_log(sequence + len(logs), "process", "high", "Suspicious process command-line behavior detected.", indicators=[item for item in indicators if item not in injection_hits]))

        signed = process.get("signed")
        integrity = str(process.get("integrity_level") or process.get("integrity") or "").lower()
        identity_risk = 0.0
        if signed is False:
            identity_risk += 17.0
            indicators.append("unsigned_process")
        if integrity in {"system", "high", "elevated"} and signed is not True:
            identity_risk += 22.0
            indicators.append("unsigned_elevated_process")
        if parent_name in _SUSPICIOUS_PARENTS and command_line:
            identity_risk += 14.0
            indicators.append("office_or_browser_parent_process")
        breakdown["identity_risk"] = _clip(identity_risk)
        risk += identity_risk

        resource_risk = 0.0
        for key, threshold, penalty in (("cpu_percent", 95.0, 10.0), ("memory_percent", 90.0, 10.0), ("open_handles", 20_000, 12.0)):
            try:
                if float(process.get(key, 0.0) or 0.0) >= threshold:
                    resource_risk += penalty
                    indicators.append(f"high_{key}")
            except (TypeError, ValueError):
                indicators.append(f"invalid_{key}")
                resource_risk += 4.0
        breakdown["resource_risk"] = _clip(resource_risk)
        risk += resource_risk
        risk = _clip(risk)
        if risk >= 75.0 and (injection_hits or command_risk >= 45):
            hard_block = True
        logs.append(_log(sequence + len(logs), "process", "critical" if hard_block else ("high" if risk >= 75 else "info"), "Process snapshot scored.", pid=pid, name=name, risk_score=_round(risk)))
        return ProcessSnapshotReport(
            pid=pid,
            name=name,
            risk_score=_round(risk),
            hard_block=hard_block,
            indicators=sorted(set(indicators)),
            metadata={
                "parent_name": parent_name or None,
                "signed": signed,
                "integrity_level": integrity or None,
                "behavior_tag_count": len(behavior_tags),
                "command_line_hash": _hash_text(command_line) if command_line else None,
                "threat_breakdown": {key: _round(value) for key, value in breakdown.items()},
            },
            forensic_logs=logs,
        )

    @staticmethod
    def _breakdown_value(report: ProcessSnapshotReport, key: str) -> float:
        values = report.metadata.get("threat_breakdown", {})
        try:
            return float(values.get(key, 0.0))
        except (TypeError, ValueError):
            return 0.0


# ---------------------------------------------------------------------------
# 4. Threat-filtering orchestration and FastAPI endpoint
# ---------------------------------------------------------------------------


class ThreatFilterEngine:
    """Coordinate file, URL, code, and process checks into one policy verdict."""

    def __init__(self) -> None:
        self.file_scanner = FileIntegrityScanner()
        self.url_filter = URLPhishingFilter()
        self.process_detector = ProcessAnomalyDetector()

    def filter_threat(self, payload: ThreatFilterInput) -> ThreatFilterResult:
        logs: list[ForensicLog] = []
        components: dict[str, Any] = {}
        risk_values: list[float] = []
        hard_block = False
        policy_reasons: list[str] = []
        payload_type = (payload.payload_type or "auto").strip().lower()
        if payload_type == "js":
            payload_type = "code"

        if payload.file_bytes is not None:
            try:
                file_report = self.file_scanner.scan(
                    payload.file_name or "uploaded-payload",
                    payload.file_bytes,
                    declared_sha256=payload.declared_sha256,
                    allowed_sha256=payload.allowed_sha256,
                    blocked_sha256=payload.blocked_sha256,
                    claimed_mime=str(payload.metadata.get("claimed_mime")) if payload.metadata.get("claimed_mime") else None,
                )
                components["file_integrity"] = file_report.to_dict()
                risk_values.append(file_report.risk_score)
                hard_block = hard_block or file_report.hard_block
                logs.extend(file_report.forensic_logs)
                if file_report.hard_block:
                    policy_reasons.append("file integrity policy produced a hard block")
            except (TypeError, ValueError) as exc:
                components["file_integrity"] = {"error": str(exc), "risk_score": 90.0}
                risk_values.append(90.0)
                hard_block = True
                policy_reasons.append("file payload could not be safely inspected")
                logs.append(_log(len(logs) + 1, "file", "critical", "File inspection failed closed.", error=str(exc)))

        if payload.url:
            try:
                url_report = self.url_filter.inspect(payload.url, payload.network_payload)
                components["url_filter"] = url_report.to_dict()
                risk_values.append(url_report.risk_score)
                hard_block = hard_block or url_report.hard_block
                logs.extend(url_report.forensic_logs)
                if url_report.hard_block:
                    policy_reasons.append("URL or network payload matched a hard-block signature")
            except ValueError as exc:
                components["url_filter"] = {"error": str(exc), "risk_score": 90.0}
                risk_values.append(90.0)
                hard_block = True
                policy_reasons.append("URL could not be safely normalized")
                logs.append(_log(len(logs) + 1, "url", "critical", "URL inspection failed closed.", error=str(exc)))

        if payload.source_code:
            code_report = self._inspect_code(payload.source_code, payload.language)
            components["code_analysis"] = code_report
            code_risk = float(code_report.get("risk_score", 60.0))
            risk_values.append(code_risk)
            hard_block = hard_block or bool(code_report.get("hard_block", False))
            logs.extend(self._dict_logs(code_report.get("forensic_logs", []), "code"))
            if code_report.get("hard_block"):
                policy_reasons.append("code analysis produced a malicious or high-confidence injection verdict")

        if payload.processes:
            process_report = self.process_detector.analyze(payload.processes)
            components["process_anomalies"] = process_report.to_dict()
            risk_values.append(process_report.threat_level_index)
            hard_block = hard_block or process_report.hard_block
            logs.extend(process_report.forensic_logs)
            if process_report.hard_block:
                policy_reasons.append("process telemetry contains an unauthorized memory-injection signature")

        if not risk_values:
            raise ValueError("provide file content, source_code, url, or a process snapshot")

        values = np.asarray(risk_values, dtype=np.float64)
        maximum = float(np.max(values))
        average = float(np.mean(values))
        threat_level_index = _clip(0.68 * maximum + 0.32 * average)
        if hard_block or threat_level_index >= 75.0:
            action = BLOCK
        elif threat_level_index >= 40.0:
            action = QUARANTINE
        else:
            action = ALLOW
        if action == BLOCK and not policy_reasons:
            policy_reasons.append("aggregate threat index crossed the block threshold")
        if action == QUARANTINE and not policy_reasons:
            policy_reasons.append("aggregate threat index requires analyst review")
        if action == ALLOW and not policy_reasons:
            policy_reasons.append("no high-confidence threat signal crossed the quarantine threshold")

        # Confidence reflects how many independent engines supplied evidence,
        # not how safe the payload is. A malicious payload can have confidence
        # near 100 when several engines agree.
        engine_count = len(components)
        confidence = _clip(82.0 + engine_count * 4.0 + min(8.0, len(logs) / 4.0))
        component_scores = {
            "file_integrity": _round(float(components["file_integrity"].get("risk_score", 0.0))) if "file_integrity" in components else 0.0,
            "url_phishing": _round(float(components["url_filter"].get("risk_score", 0.0))) if "url_filter" in components else 0.0,
            "code_injection": _round(float(components["code_analysis"].get("risk_score", 0.0))) if "code_analysis" in components else 0.0,
            "process_anomaly": _round(float(components["process_anomalies"].get("threat_level_index", 0.0))) if "process_anomalies" in components else 0.0,
        }
        summary = {
            ALLOW: "No high-confidence threat detected; payload may proceed.",
            QUARANTINE: "Suspicious signals detected; hold payload for analyst review.",
            BLOCK: "Threat policy blocked the payload before execution or delivery.",
        }[action]
        logs.append(_log(len(logs) + 1, "policy", "critical" if action == BLOCK else ("high" if action == QUARANTINE else "info"), summary, action=action, threat_level_index=_round(threat_level_index)))
        canonical_id = json.dumps(
            {
                "file_sha256": components.get("file_integrity", {}).get("hashes", {}).get("sha256"),
                "url_hash": components.get("url_filter", {}).get("url_hash"),
                "code_hash": _hash_text(payload.source_code) if payload.source_code else None,
                "processes": [item.get("pid") for item in payload.processes],
                "action": action,
            },
            sort_keys=True,
        )
        return ThreatFilterResult(
            analysis_id=_hash_text(canonical_id)[:16],
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            action=action,
            threat_level_index=_round(threat_level_index),
            confidence_index=_round(confidence),
            summary=summary,
            threat_breakdown=component_scores,
            components=components,
            forensic_logs=logs,
            policy_reasons=policy_reasons,
        )

    @staticmethod
    def _dict_logs(entries: Sequence[Mapping[str, Any]], stage: str) -> list[ForensicLog]:
        logs: list[ForensicLog] = []
        for index, entry in enumerate(entries, start=1):
            logs.append(ForensicLog(index, stage, str(entry.get("level", "info")), str(entry.get("message", "Code analysis event")), dict(entry.get("evidence", {}))))
        return logs

    @staticmethod
    def _inspect_code(source_code: str, language: str) -> dict[str, Any]:
        if len(source_code) > MAX_TEXT_CHARS:
            return {"risk_score": 90.0, "hard_block": True, "error": f"source_code exceeds the {MAX_TEXT_CHARS:,}-character limit", "forensic_logs": [{"level": "critical", "message": "Code inspection failed closed", "evidence": {}}]}
        try:
            # Import lazily so threat_filter_core remains independently
            # importable and does not create a backend_core circular import.
            backend_module = sys.modules.get("backend_core") or sys.modules.get("__main__")
            analyze_code = getattr(backend_module, "analyze_code", None)
            if analyze_code is None:
                from backend_core import analyze_code  # type: ignore[no-redef]

            report = analyze_code(source_code, language)
            status = str(report.verification_status)
            if status == "MALICIOUS":
                risk_score = 92.0
                hard_block = True
            elif status == "REVIEW_REQUIRED":
                risk_score = 58.0
                hard_block = False
            else:
                risk_score = max(0.0, 18.0 + (100.0 - float(report.trust_score)) * 0.35)
                hard_block = False
            return {
                "language": report.language,
                "risk_score": _round(risk_score),
                "hard_block": hard_block,
                "trust_score": report.trust_score,
                "verification_status": status,
                "confidence_index": report.confidence_index,
                "anomaly_flags": report.anomaly_flags,
                "syntax_errors": report.syntax_errors,
                "threat_breakdown": report.threat_breakdown,
                "forensic_logs": [{"level": "info", "message": message, "evidence": {}} for message in report.analysis_logs],
            }
        except Exception as exc:  # fail closed for an unavailable code engine
            return {"risk_score": 72.0, "hard_block": False, "error": "code analyzer unavailable", "forensic_logs": [{"level": "high", "message": "Code inspection unavailable; payload quarantined conservatively", "evidence": {"error_type": type(exc).__name__}}]}


class ThreatFilterRequest(BaseModel):
    """JSON representation of file, code, URL, and process evidence."""

    payload_type: str = Field(default="auto", description="auto, file, code, url, or process")
    type: Optional[str] = Field(default=None, description="Alias for payload_type")
    payload: Any = Field(default=None, description="Optional generic payload alias")
    file_name: Optional[str] = Field(default=None, description="Filename for a base64 or multipart file payload")
    file_content_base64: Optional[str] = Field(default=None, description="Base64-encoded file bytes")
    content_base64: Optional[str] = Field(default=None, description="Alias for file_content_base64")
    file_base64: Optional[str] = Field(default=None, description="Alias for file_content_base64")
    file_content: Optional[str] = Field(default=None, description="Plain UTF-8 file content for JSON clients")
    declared_sha256: Optional[str] = None
    allowed_sha256: list[str] = Field(default_factory=list)
    blocked_sha256: list[str] = Field(default_factory=list)
    source_code: Optional[str] = None
    code: Optional[str] = Field(default=None, description="Alias for source_code")
    language: str = "auto"
    url: Optional[str] = None
    network_payload: Optional[str] = None
    processes: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_input(self) -> ThreatFilterInput:
        resolved_type = (self.type or self.payload_type or "auto").strip().lower()
        if resolved_type == "js":
            resolved_type = "code"
        generic_payload = self.payload
        generic_text = generic_payload if isinstance(generic_payload, str) else None
        source_code = self.source_code if self.source_code is not None else self.code
        url = self.url
        processes: Sequence[Mapping[str, Any]] = self.processes
        if resolved_type in {"process", "processes"} and isinstance(generic_payload, list) and not processes:
            processes = tuple(item for item in generic_payload if isinstance(item, Mapping))
        if generic_text is not None:
            if resolved_type in {"url", "web", "uri"} and url is None:
                url = generic_text
            elif resolved_type in {"code", "script", "source"} and source_code is None:
                source_code = generic_text
            elif resolved_type == "auto" and source_code is None and url is None:
                if re.match(r"^(?:https?|javascript|data|vbscript):", generic_text.strip(), re.I):
                    url = generic_text
                else:
                    source_code = generic_text
        encoded_file = self.file_content_base64 or self.content_base64 or self.file_base64
        if encoded_file:
            file_bytes = _decode_base64_payload(encoded_file)
        elif self.file_content is not None:
            file_bytes = self.file_content.encode("utf-8")
        elif resolved_type in {"file", "binary"} and generic_text is not None:
            file_bytes = _decode_base64_payload(generic_text)
        else:
            file_bytes = None
        return ThreatFilterInput(
            payload_type=resolved_type,
            file_name=self.file_name,
            file_bytes=file_bytes,
            declared_sha256=self.declared_sha256,
            allowed_sha256=tuple(self.allowed_sha256),
            blocked_sha256=tuple(self.blocked_sha256),
            source_code=source_code,
            language=self.language,
            url=url,
            network_payload=self.network_payload,
            processes=tuple(processes),
            metadata=self.metadata,
        )


engine = ThreatFilterEngine()


def scan_file_integrity(
    file_name: str,
    file_bytes: bytes,
    *,
    declared_sha256: Optional[str] = None,
    allowed_sha256: Sequence[str] = (),
    blocked_sha256: Sequence[str] = (),
    claimed_mime: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience function for direct file/binary integrity inspection."""

    return FileIntegrityScanner().scan(
        file_name,
        file_bytes,
        declared_sha256=declared_sha256,
        allowed_sha256=allowed_sha256,
        blocked_sha256=blocked_sha256,
        claimed_mime=claimed_mime,
    ).to_dict()


def analyze_url(url: str, network_payload: Optional[str] = None) -> dict[str, Any]:
    """Convenience function for direct URL and web-payload inspection."""

    return URLPhishingFilter().inspect(url, network_payload).to_dict()


def detect_process_anomalies(processes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Convenience function for direct simulated process monitoring."""

    return ProcessAnomalyDetector().analyze(processes).to_dict()


def run_threat_filter(payload: ThreatFilterInput | ThreatFilterRequest) -> dict[str, Any]:
    """Run the complete pipeline outside HTTP with the same response shape."""

    normalized = payload.to_input() if isinstance(payload, ThreatFilterRequest) else payload
    return engine.filter_threat(normalized).to_dict()


threat_router = APIRouter()


def _validate_model(data: Mapping[str, Any]) -> ThreatFilterRequest:
    """Support Pydantic v2 and v1 without tying the module to one version."""

    validator = getattr(ThreatFilterRequest, "model_validate", None)
    if validator:
        return validator(data)
    return ThreatFilterRequest.parse_obj(data)


async def _request_to_model(request: Request) -> ThreatFilterRequest:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type or not content_type:
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
        if not isinstance(body, Mapping):
            raise HTTPException(status_code=422, detail="request body must be a JSON object")
        try:
            return _validate_model(body)
        except Exception as exc:
            raise HTTPException(status_code=422, detail="request body failed threat-filter validation") from exc

    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        try:
            form = await request.form()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="multipart form parsing is unavailable or invalid") from exc
        data: dict[str, Any] = {key: value for key, value in form.items() if not hasattr(value, "read")}
        for key in ("processes", "allowed_sha256", "blocked_sha256", "metadata"):
            if isinstance(data.get(key), str) and data[key].strip():
                try:
                    data[key] = json.loads(data[key])
                except json.JSONDecodeError as exc:
                    raise HTTPException(status_code=422, detail=f"form field '{key}' must contain valid JSON") from exc
        upload = form.get("file") or form.get("upload")
        if upload is not None and hasattr(upload, "read"):
            raw_bytes = await upload.read()
            if len(raw_bytes) > MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail=f"uploaded file exceeds the {MAX_FILE_BYTES:,}-byte limit")
            data["file_name"] = getattr(upload, "filename", None) or data.get("file_name") or "multipart-upload"
            data["file_content_base64"] = base64.b64encode(raw_bytes).decode("ascii")
            data.setdefault("payload_type", "file")
        try:
            return _validate_model(data)
        except Exception as exc:
            raise HTTPException(status_code=422, detail="multipart fields failed threat-filter validation") from exc

    # Raw octet streams are treated as files. This keeps the endpoint useful to
    # lightweight agents that cannot construct multipart forms.
    if content_type == "application/octet-stream" or content_type.startswith("application/octet-stream;"):
        raw_bytes = await request.body()
        if len(raw_bytes) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail=f"uploaded file exceeds the {MAX_FILE_BYTES:,}-byte limit")
        return ThreatFilterRequest(
            payload_type="file",
            file_name=request.headers.get("x-file-name", "raw-upload"),
            file_content_base64=base64.b64encode(raw_bytes).decode("ascii"),
        )
    raise HTTPException(status_code=415, detail="use JSON, multipart/form-data, or application/octet-stream")


@threat_router.post("/api/v1/filter-threat")
async def filter_threat(request: Request) -> dict[str, Any]:
    """Run the active endpoint-protection pipeline and return an action verdict."""

    payload = await _request_to_model(request)
    try:
        normalized = payload.to_input()
        result = engine.filter_threat(normalized)
        return result.to_dict()
    except PayloadDecodeError as exc:
        # Invalid encoded file data is treated as an invalid request rather than
        # silently inspecting a different byte stream.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - final fail-closed API guard
        raise HTTPException(status_code=500, detail="Threat filtering failed safely") from exc


app = FastAPI(
    title="Veritas Inspector Threat Filtering Core",
    version="1.0.0",
    description="Read-only file, URL, code, and process threat filtering service.",
)
app.include_router(threat_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("threat_filter_core:app", host="0.0.0.0", port=8001, reload=False)
