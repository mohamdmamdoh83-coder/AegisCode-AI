"""Veritas Inspector mathematical code-inspection backend.

This module intentionally has no UI concerns.  It provides a small, deterministic
analysis core and a FastAPI adapter around it:

    POST /api/v1/inspect-code

The Python path uses the standard-library ``ast`` module.  JavaScript is parsed
with a dependency-free lexical/structural parser so the service only requires
FastAPI and NumPy.  The JavaScript parser is deliberately conservative: a
mismatched delimiter or unterminated literal is returned as a syntax anomaly
instead of crashing the request.

Run directly with:

    python backend_core.py

Or serve it with:

    uvicorn backend_core:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import ast
import hashlib
import io
import math
import re
import tokenize
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from api_security import install_api_protections


MAX_SOURCE_CHARS = 200_000
SUPPORTED_LANGUAGES = {"auto", "python", "py", "javascript", "js"}

SECURE = "SECURE"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
MALICIOUS = "MALICIOUS"


class UnsupportedLanguageError(ValueError):
    """Raised when a caller asks for a language outside the supported set."""


class SyntaxAnomaly(ValueError):
    """A recoverable syntax anomaly found by the JavaScript lexer."""

    def __init__(self, message: str, line: int = 1, column: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column

    def formatted(self) -> str:
        return f"line {self.line}, column {self.column}: {self.message}"


@dataclass(slots=True)
class SyntaxNode:
    """A small common syntax-node representation for Python and JavaScript."""

    kind: str
    value: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    depth: int = 0
    children: list["SyntaxNode"] = field(default_factory=list)


@dataclass(slots=True)
class Lexeme:
    """Language-neutral token used for entropy and JavaScript parsing."""

    kind: str
    value: str
    line: int
    column: int


@dataclass(slots=True)
class AnomalyMetrics:
    """Normalized metrics produced by :func:`analyze_code`.

    All risk and entropy fields are percentages in the inclusive range 0-100.
    ``loop_density`` is the raw ratio of loop syntax nodes to all syntax nodes;
    the corresponding percentage used by the scorer is exposed as
    ``threat_breakdown['loop_density_risk']``.
    """

    language: str
    source_hash: str
    syntax_valid: bool
    line_count: int
    logical_line_count: int
    token_count: int
    syntax_node_count: int
    syntax_node_types: dict[str, int]
    cyclomatic_complexity: float
    loop_count: int
    loop_density: float
    character_entropy: float
    token_entropy: float
    entropy_index: float
    obfuscation_index: float
    injection_index: float
    threat_breakdown: dict[str, float]
    anomaly_flags: list[str]
    syntax_errors: list[str]
    analysis_logs: list[str]


@dataclass(slots=True)
class TrustScore:
    """Deterministic score and decision derived from anomaly metrics."""

    trust_score: float
    verification_status: str
    confidence_index: float
    risk_score: float
    rationale: list[str]


@dataclass(slots=True)
class InspectionResult:
    """Serializable result returned by the service and useful in unit tests."""

    analysis_id: str
    analyzed_at: str
    language: str
    trust_score: float
    verification_status: str
    confidence_index: float
    threat_breakdown: dict[str, float]
    metrics: dict[str, Any]
    anomaly_flags: list[str]
    syntax_errors: list[str]
    analysis_logs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# These patterns are intentionally explainable and weighted.  They are not
# signatures for a single malware family; they are mathematical risk signals
# that become one input into the final deterministic trust score.
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("dynamic_execution", re.compile(r"\b(?:eval|exec|compile|Function)\s*\(", re.I), 27.0),
    ("runtime_import", re.compile(r"\b(?:__import__|importlib\.import_module|require)\s*\(", re.I), 19.0),
    ("process_spawn", re.compile(r"\b(?:subprocess|child_process|os\.system|powershell|cmd\.exe)\b", re.I), 28.0),
    ("encoded_decoder", re.compile(r"\b(?:atob|btoa|base64\.(?:b64)?decode|fromCharCode|unescape)\b", re.I), 23.0),
    ("credential_or_cookie_access", re.compile(r"\b(?:document\.cookie|localStorage|sessionStorage|keychain|password|credential)\b", re.I), 20.0),
    ("html_injection", re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", re.I), 18.0),
    ("redirect_or_network_sink", re.compile(r"\b(?:window\.location|location\.href|fetch|XMLHttpRequest|requests?\.(?:get|post))\b", re.I), 10.0),
    ("destructive_shell", re.compile(r"(?:rm\s+-rf|curl\s+[^\n]+\|\s*(?:sh|bash)|wget\s+[^\n]+\|\s*(?:sh|bash))", re.I), 35.0),
)

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
_ESCAPED_PAYLOAD_RE = re.compile(r"(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){3,}", re.I)
_LONG_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]{32,}\b")


# ---------------------------------------------------------------------------
# Generic numerical helpers
# ---------------------------------------------------------------------------


def _clip(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    """Return a Python float clipped to a closed interval."""

    return float(np.clip(float(value), lower, upper))


def _round(value: float, digits: int = 2) -> float:
    """Round NumPy scalars after converting them to JSON-safe Python floats."""

    return round(float(value), digits)


def _shannon_entropy(values: Iterable[str], fixed_cardinality: Optional[int] = None) -> float:
    """Return normalized Shannon entropy as a 0-100 percentage.

    A fixed 95-symbol printable alphabet is used for characters.  Token entropy
    uses the observed stream length as its upper bound, preventing a short
    two-symbol source from being reported as maximally complex merely because it
    contains two equally likely symbols.
    """

    values_list = list(values)
    if len(values_list) < 2:
        return 0.0

    counts = Counter(values_list)
    probabilities = np.asarray(list(counts.values()), dtype=np.float64)
    probabilities /= float(len(values_list))
    entropy_bits = -float(np.sum(probabilities * np.log2(probabilities)))

    if fixed_cardinality is None:
        cardinality = max(2, min(len(values_list), 64))
    else:
        cardinality = max(2, fixed_cardinality)
    maximum = math.log2(cardinality)
    return _clip((entropy_bits / maximum) * 100.0 if maximum else 0.0)


def _source_hash(source_code: str) -> str:
    return hashlib.sha256(source_code.encode("utf-8")).hexdigest()


def _logical_line_count(source_code: str) -> int:
    return max(
        1,
        sum(
            1
            for line in source_code.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "//"))
        ),
    )


def _normalise_language(language: str, source_code: str, filename: Optional[str] = None) -> str:
    requested = (language or "auto").strip().lower()
    if requested not in SUPPORTED_LANGUAGES:
        raise UnsupportedLanguageError(
            f"Unsupported language '{language}'. Use one of: python, javascript, or auto."
        )
    if requested in {"python", "py"}:
        return "python"
    if requested in {"javascript", "js"}:
        return "javascript"
    if filename:
        lower_name = filename.lower()
        if lower_name.endswith((".py", ".pyw")):
            return "python"
        if lower_name.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
            return "javascript"

    # Explicit-looking language markers make auto mode predictable.  Python is
    # the conservative default because its AST parser is stricter and safer.
    python_markers = re.search(
        r"(?m)^\s*(?:def\s+\w+\s*\(|class\s+\w+\s*[:(]|from\s+\S+\s+import\s+|if\s+__name__\s*==)",
        source_code,
    )
    javascript_markers = re.search(
        r"(?m)\b(?:const|let|var|function|console\.log|document\.|window\.)\b|=>",
        source_code,
    )
    if javascript_markers and not python_markers:
        return "javascript"
    return "python"


# ---------------------------------------------------------------------------
# Python AST and JavaScript structural parsing
# ---------------------------------------------------------------------------


def _python_syntax_nodes(tree: ast.AST) -> tuple[SyntaxNode, list[SyntaxNode]]:
    """Convert a Python AST into common syntax nodes and a flat node index."""

    flat_nodes: list[SyntaxNode] = []

    def visit(node: ast.AST, depth: int = 0) -> SyntaxNode:
        syntax_node = SyntaxNode(
            kind=type(node).__name__,
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", None),
            depth=depth,
        )
        flat_nodes.append(syntax_node)
        syntax_node.children = [visit(child, depth + 1) for child in ast.iter_child_nodes(node)]
        return syntax_node

    return visit(tree), flat_nodes


def _python_lexemes(source_code: str) -> tuple[list[Lexeme], list[str]]:
    """Tokenize Python for entropy metrics, retaining recoverable errors."""

    lexemes: list[Lexeme] = []
    errors: list[str] = []
    ignored = {
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.NEWLINE,
        tokenize.NL,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.COMMENT,
    }
    try:
        stream = tokenize.generate_tokens(io.StringIO(source_code).readline)
        for token in stream:
            if token.type in ignored:
                continue
            lexemes.append(Lexeme(tokenize.tok_name[token.type], token.string, token.start[0], token.start[1]))
    except (tokenize.TokenError, IndentationError) as exc:
        message = str(exc)
        errors.append(f"Python tokenization anomaly: {message}")
    return lexemes, errors


_JS_IDENTIFIER_START = re.compile(r"[A-Za-z_$]")
_JS_IDENTIFIER_PART = re.compile(r"[A-Za-z0-9_$]")
_JS_NUMBER_START = re.compile(r"[0-9]")
_JS_MULTI_OPERATORS = tuple(
    sorted(
        {
            "===",
            "!==",
            ">>>=",
            "**=",
            "&&=",
            "||=",
            "??=",
            "=>",
            "==",
            "!=",
            "<=",
            ">=",
            "++",
            "--",
            "&&",
            "||",
            "??",
            "?.",
            "**",
            "+=",
            "-=",
            "*=",
            "/=",
            "%=",
            "<<",
            ">>",
            ">>>",
            "&=",
            "|=",
            "^=",
        },
        key=len,
        reverse=True,
    )
)
_JS_OPEN_TO_CLOSE = {"{": "}", "(": ")", "[": "]"}
_JS_CLOSE_TO_OPEN = {value: key for key, value in _JS_OPEN_TO_CLOSE.items()}
_JS_REGEX_INTRODUCERS = {
    "return",
    "throw",
    "case",
    "typeof",
    "new",
    "delete",
    "void",
    "await",
    "in",
    "of",
    "instanceof",
    "yield",
}
_JS_REGEX_FLAGS = frozenset("gimsuyad")
_JS_HEX_DIGIT = re.compile(r"[0-9A-Fa-f_]")
_JS_DIGIT = re.compile(r"[0-9_]")


def _advance_position(character: str, line: int, column: int) -> tuple[int, int]:
    if character == "\n":
        return line + 1, 1
    return line, column + 1


def _javascript_can_start_regex(previous: Optional[Lexeme]) -> bool:
    """Return whether ``/`` at the current position may begin a regexp literal."""

    if previous is None:
        return True
    if previous.kind == "punctuation" and previous.value in {"(", "[", "{", ",", ";", ":", "?", "~", "!", "${"}:
        return True
    if previous.kind == "operator":
        return True
    if previous.kind == "identifier" and previous.value in _JS_REGEX_INTRODUCERS:
        return True
    return False


def _javascript_lexemes(source_code: str) -> tuple[list[Lexeme], list[str]]:
    """Tokenize JavaScript and collect delimiter/literal syntax anomalies.

    The lexer remains conservative and dependency-free.  Improvements over the
    original scanner:

    * numeric literals no longer swallow following identifiers (``1.toString``)
    * template interpolations contribute nested expression tokens so inner
      delimiter errors are visible
    * regexp literals are recognized in expression position so ``/pattern/`` is
      not split into division operators
    """

    lexemes: list[Lexeme] = []
    errors: list[str] = []
    index = 0
    line = 1
    column = 1
    length = len(source_code)

    def add_error(message: str, error_line: int, error_column: int) -> None:
        errors.append(f"JavaScript syntax anomaly at line {error_line}, column {error_column}: {message}")

    def consume_escape(at: int, at_line: int, at_column: int) -> tuple[int, int, int]:
        at_line, at_column = _advance_position(source_code[at], at_line, at_column)
        at += 1
        if at < length:
            at_line, at_column = _advance_position(source_code[at], at_line, at_column)
            at += 1
        return at, at_line, at_column

    def consume_quoted(quote: str, at: int, at_line: int, at_column: int, start_line: int, start_column: int) -> tuple[int, int, int, bool]:
        start = at
        at += 1
        at_line, at_column = _advance_position(quote, at_line, at_column)
        closed = False
        while at < length:
            current = source_code[at]
            if current == "\\":
                at, at_line, at_column = consume_escape(at, at_line, at_column)
                continue
            if current == quote:
                at_line, at_column = _advance_position(current, at_line, at_column)
                at += 1
                closed = True
                break
            if current in {"\n", "\r"}:
                add_error("unterminated string literal", start_line, start_column)
                break
            at_line, at_column = _advance_position(current, at_line, at_column)
            at += 1
        if not closed and (not errors or "unterminated string literal" not in errors[-1]):
            add_error("unterminated string or template literal", start_line, start_column)
        if closed:
            lexemes.append(Lexeme("string", source_code[start:at], start_line, start_column))
        return at, at_line, at_column, closed

    def consume_template(at: int, at_line: int, at_column: int, start_line: int, start_column: int) -> tuple[int, int, int, bool]:
        """Lex a template literal, emitting nested tokens for ``${...}`` bodies."""

        chunk_start = at
        chunk_line, chunk_column = at_line, at_column
        at += 1
        at_line, at_column = _advance_position("`", at_line, at_column)
        closed = False
        while at < length:
            current = source_code[at]
            if current == "\\":
                at, at_line, at_column = consume_escape(at, at_line, at_column)
                continue
            if current == "`":
                at_line, at_column = _advance_position(current, at_line, at_column)
                at += 1
                lexemes.append(Lexeme("string", source_code[chunk_start:at], chunk_line, chunk_column))
                closed = True
                break
            if current == "$" and at + 1 < length and source_code[at + 1] == "{":
                lexemes.append(Lexeme("string", source_code[chunk_start:at], chunk_line, chunk_column))
                lexemes.append(Lexeme("punctuation", "${", at_line, at_column))
                at += 2
                at_column += 2
                at, at_line, at_column, inner_closed = consume_interpolation(at, at_line, at_column)
                if not inner_closed:
                    add_error("unterminated template interpolation", start_line, start_column)
                    return at, at_line, at_column, False
                chunk_start = at
                chunk_line, chunk_column = at_line, at_column
                continue
            at_line, at_column = _advance_position(current, at_line, at_column)
            at += 1
        if not closed:
            add_error("unterminated string or template literal", start_line, start_column)
        return at, at_line, at_column, closed

    def consume_interpolation(at: int, at_line: int, at_column: int) -> tuple[int, int, int, bool]:
        """Lex tokens inside a template interpolation until the matching ``}``."""

        depth = 1
        while at < length:
            character = source_code[at]
            if character.isspace():
                at_line, at_column = _advance_position(character, at_line, at_column)
                at += 1
                continue
            token_line, token_column = at_line, at_column
            if source_code.startswith("//", at):
                at += 2
                at_column += 2
                while at < length and source_code[at] != "\n":
                    at_column += 1
                    at += 1
                continue
            if source_code.startswith("/*", at):
                at += 2
                at_column += 2
                closed_comment = False
                while at < length:
                    if source_code.startswith("*/", at):
                        at += 2
                        at_column += 2
                        closed_comment = True
                        break
                    at_line, at_column = _advance_position(source_code[at], at_line, at_column)
                    at += 1
                if not closed_comment:
                    add_error("unterminated block comment", token_line, token_column)
                    return at, at_line, at_column, False
                continue
            if character in {"'", '"'}:
                at, at_line, at_column, closed = consume_quoted(character, at, at_line, at_column, token_line, token_column)
                if not closed:
                    return at, at_line, at_column, False
                continue
            if character == "`":
                at, at_line, at_column, closed = consume_template(at, at_line, at_column, token_line, token_column)
                if not closed:
                    return at, at_line, at_column, False
                continue
            if character == "{":
                lexemes.append(Lexeme("punctuation", "{", token_line, token_column))
                depth += 1
                at += 1
                at_column += 1
                continue
            if character == "}":
                depth -= 1
                at += 1
                at_column += 1
                if depth == 0:
                    lexemes.append(Lexeme("punctuation", "}", token_line, token_column))
                    return at, at_line, at_column, True
                lexemes.append(Lexeme("punctuation", "}", token_line, token_column))
                continue
            at, at_line, at_column = consume_code_token(at, at_line, at_column)
        return at, at_line, at_column, False

    def consume_number(at: int, at_line: int, at_column: int) -> tuple[int, int, int]:
        start = at
        start_line, start_column = at_line, at_column
        if source_code[at] == "0" and at + 1 < length and source_code[at + 1] in "xXoObB":
            at += 2
            at_column += 2
            while at < length and _JS_HEX_DIGIT.fullmatch(source_code[at]):
                at += 1
                at_column += 1
        else:
            if source_code[at] == ".":
                at += 1
                at_column += 1
            while at < length and _JS_DIGIT.fullmatch(source_code[at]):
                at += 1
                at_column += 1
            if at < length and source_code[at] == "." and at + 1 < length and source_code[at + 1].isdigit():
                at += 1
                at_column += 1
                while at < length and _JS_DIGIT.fullmatch(source_code[at]):
                    at += 1
                    at_column += 1
            if at < length and source_code[at] in "eE":
                lookahead = at + 1
                if lookahead < length and source_code[lookahead] in "+-":
                    lookahead += 1
                if lookahead < length and source_code[lookahead].isdigit():
                    at_column += lookahead - at
                    at = lookahead
                    while at < length and _JS_DIGIT.fullmatch(source_code[at]):
                        at += 1
                        at_column += 1
        if at < length and source_code[at] == "n":
            at += 1
            at_column += 1
        lexemes.append(Lexeme("number", source_code[start:at], start_line, start_column))
        return at, at_line, at_column

    def consume_regex(at: int, at_line: int, at_column: int) -> tuple[int, int, int, bool]:
        start = at
        start_line, start_column = at_line, at_column
        at += 1
        at_column += 1
        in_class = False
        closed = False
        while at < length:
            current = source_code[at]
            if current == "\n":
                break
            if current == "\\":
                at, at_line, at_column = consume_escape(at, at_line, at_column)
                continue
            if current == "[" and not in_class:
                in_class = True
            elif current == "]" and in_class:
                in_class = False
            elif current == "/" and not in_class:
                at_line, at_column = _advance_position(current, at_line, at_column)
                at += 1
                closed = True
                break
            at_line, at_column = _advance_position(current, at_line, at_column)
            at += 1
        if closed:
            while at < length and source_code[at] in _JS_REGEX_FLAGS:
                at += 1
                at_column += 1
            lexemes.append(Lexeme("regex", source_code[start:at], start_line, start_column))
            return at, at_line, at_column, True
        add_error("unterminated regular expression literal", start_line, start_column)
        return at, at_line, at_column, False

    def consume_code_token(at: int, at_line: int, at_column: int) -> tuple[int, int, int]:
        character = source_code[at]
        token_line, token_column = at_line, at_column
        previous = lexemes[-1] if lexemes else None
        if _JS_IDENTIFIER_START.fullmatch(character):
            start = at
            at += 1
            at_column += 1
            while at < length and _JS_IDENTIFIER_PART.fullmatch(source_code[at]):
                at += 1
                at_column += 1
            lexemes.append(Lexeme("identifier", source_code[start:at], token_line, token_column))
            return at, at_line, at_column
        if _JS_NUMBER_START.fullmatch(character) or (
            character == "." and at + 1 < length and source_code[at + 1].isdigit()
        ):
            return consume_number(at, at_line, at_column)
        operator = next((candidate for candidate in _JS_MULTI_OPERATORS if source_code.startswith(candidate, at)), None)
        if operator:
            lexemes.append(Lexeme("operator", operator, token_line, token_column))
            return at + len(operator), at_line, at_column + len(operator)
        if character == "/" and _javascript_can_start_regex(previous):
            at, at_line, at_column, closed = consume_regex(at, at_line, at_column)
            if not closed:
                return at, at_line, at_column
            return at, at_line, at_column
        if character in "{}()[];,.?:":
            lexemes.append(Lexeme("punctuation", character, token_line, token_column))
            return at + 1, at_line, at_column + 1
        if character in "=+-*/%!<>|&^~":
            lexemes.append(Lexeme("operator", character, token_line, token_column))
            return at + 1, at_line, at_column + 1
        add_error(f"unexpected character {character!r}", token_line, token_column)
        lexemes.append(Lexeme("unknown", character, token_line, token_column))
        return at + 1, at_line, at_column + 1

    while index < length:
        character = source_code[index]

        if character.isspace():
            line, column = _advance_position(character, line, column)
            index += 1
            continue

        start_line, start_column = line, column

        # JavaScript comments are not syntax nodes for scoring, but a block
        # comment must still be closed to avoid accepting truncated code.
        if source_code.startswith("//", index):
            index += 2
            column += 2
            while index < length and source_code[index] != "\n":
                column += 1
                index += 1
            continue
        if source_code.startswith("/*", index):
            index += 2
            column += 2
            closed = False
            while index < length:
                if source_code.startswith("*/", index):
                    index += 2
                    column += 2
                    closed = True
                    break
                line, column = _advance_position(source_code[index], line, column)
                index += 1
            if not closed:
                add_error("unterminated block comment", start_line, start_column)
                break
            continue

        if character in {"'", '"'}:
            index, line, column, closed = consume_quoted(character, index, line, column, start_line, start_column)
            if not closed:
                break
            continue
        if character == "`":
            index, line, column, closed = consume_template(index, line, column, start_line, start_column)
            if not closed:
                break
            continue

        index, line, column = consume_code_token(index, line, column)

    # Build a second pass over delimiters so syntax errors are precise and the
    # structural tree can remain useful even when a close token is missing.
    delimiter_stack: list[Lexeme] = []
    for lexeme in lexemes:
        if lexeme.kind in {"string", "regex", "number"}:
            continue
        if lexeme.value == "${":
            delimiter_stack.append(Lexeme("punctuation", "{", lexeme.line, lexeme.column))
            continue
        if lexeme.value in _JS_OPEN_TO_CLOSE:
            delimiter_stack.append(lexeme)
        elif lexeme.value in _JS_CLOSE_TO_OPEN:
            expected_open = _JS_CLOSE_TO_OPEN[lexeme.value]
            if not delimiter_stack or delimiter_stack[-1].value != expected_open:
                errors.append(
                    f"JavaScript syntax anomaly at line {lexeme.line}, column {lexeme.column}: "
                    f"unexpected closing delimiter {lexeme.value!r}"
                )
            else:
                delimiter_stack.pop()
    for opening in reversed(delimiter_stack):
        errors.append(
            f"JavaScript syntax anomaly at line {opening.line}, column {opening.column}: "
            f"unclosed delimiter {opening.value!r}"
        )

    return lexemes, errors


_JS_KEYWORD_NODE_TYPES = {
    "if": "IfStatement",
    "for": "ForStatement",
    "while": "WhileStatement",
    "do": "DoStatement",
    "switch": "SwitchStatement",
    "case": "CaseClause",
    "catch": "CatchClause",
    "try": "TryStatement",
    "function": "FunctionDeclaration",
    "class": "ClassDeclaration",
    "return": "ReturnStatement",
    "throw": "ThrowStatement",
    "import": "ImportDeclaration",
    "export": "ExportDeclaration",
    "await": "AwaitExpression",
}


def _javascript_syntax_nodes(lexemes: list[Lexeme]) -> tuple[SyntaxNode, list[SyntaxNode]]:
    """Build a lightweight JavaScript structural tree from lexical tokens."""

    root = SyntaxNode("Program", depth=0)
    flat_nodes: list[SyntaxNode] = [root]
    stack: list[tuple[str, SyntaxNode]] = [("", root)]
    opening_kinds = {"{": "BlockStatement", "(": "ParenthesizedExpression", "[": "ArrayExpression"}

    for lexeme in lexemes:
        if lexeme.value in opening_kinds:
            node = SyntaxNode(
                opening_kinds[lexeme.value],
                value=lexeme.value,
                line=lexeme.line,
                column=lexeme.column,
                depth=len(stack),
            )
            stack[-1][1].children.append(node)
            flat_nodes.append(node)
            stack.append((_JS_OPEN_TO_CLOSE[lexeme.value], node))
            continue

        if lexeme.value in _JS_CLOSE_TO_OPEN:
            if len(stack) > 1 and stack[-1][0] == lexeme.value:
                stack.pop()
            continue

        if lexeme.kind == "identifier":
            kind = _JS_KEYWORD_NODE_TYPES.get(lexeme.value, "Identifier")
        elif lexeme.kind in {"string", "number", "regex"}:
            kind = "Literal"
        elif lexeme.kind == "operator":
            kind = "Operator"
        elif lexeme.kind == "unknown":
            kind = "UnknownToken"
        else:
            kind = "Punctuation"
        node = SyntaxNode(kind, value=lexeme.value, line=lexeme.line, column=lexeme.column, depth=len(stack) - 1)
        stack[-1][1].children.append(node)
        flat_nodes.append(node)

    return root, flat_nodes


# ---------------------------------------------------------------------------
# Risk metrics
# ---------------------------------------------------------------------------


def _injection_risk(source_code: str) -> tuple[float, list[str]]:
    score = 0.0
    flags: list[str] = []
    for name, pattern, weight in _INJECTION_PATTERNS:
        if pattern.search(source_code):
            score += weight
            flags.append(name)
    if len(flags) > 1:
        score += min(18.0, (len(flags) - 1) * 4.5)
    return _clip(score), flags


def _obfuscation_risk(source_code: str, lexemes: list[Lexeme], entropy_index: float) -> tuple[float, list[str]]:
    visible = "".join(character for character in source_code if not character.isspace())
    whitespace_ratio = 1.0 - (len(visible) / max(1, len(source_code)))
    long_literals = sum(1 for lexeme in lexemes if lexeme.kind == "string" and len(lexeme.value) >= 48)
    base64_hits = len(_BASE64_RE.findall(source_code))
    escaped_hits = len(_ESCAPED_PAYLOAD_RE.findall(source_code))
    long_identifiers = len(_LONG_IDENTIFIER_RE.findall(source_code))
    longest_line = max((len(line) for line in source_code.splitlines()), default=0)

    signals = min(
        100.0,
        long_literals * 22.0
        + base64_hits * 31.0
        + escaped_hits * 24.0
        + long_identifiers * 11.0
        + (18.0 if longest_line >= 240 else 0.0)
        + (12.0 if len(source_code) >= 300 and whitespace_ratio < 0.08 else 0.0),
    )
    risk = _clip(0.62 * entropy_index + 0.38 * signals)
    flags: list[str] = []
    if entropy_index >= 76:
        flags.append("high_entropy_stream")
    if long_literals or base64_hits:
        flags.append("encoded_or_opaque_literal")
    if escaped_hits:
        flags.append("escaped_payload_sequence")
    if long_identifiers:
        flags.append("high_length_identifier")
    if longest_line >= 240:
        flags.append("minified_or_packed_line")
    return risk, flags


def _python_complexity(tree: ast.AST) -> tuple[float, int, float]:
    nodes = list(ast.walk(tree))
    counts = Counter(type(node).__name__ for node in nodes)
    loop_count = sum(counts.get(kind, 0) for kind in ("For", "AsyncFor", "While"))
    decision_count = sum(
        counts.get(kind, 0)
        for kind in ("If", "For", "AsyncFor", "While", "IfExp", "ExceptHandler")
    )
    boolean_decisions = sum(
        max(0, len(node.values) - 1)
        for node in nodes
        if isinstance(node, ast.BoolOp)
    )
    match_decisions = sum(
        max(0, len(getattr(node, "cases", [])) - 1)
        for node in nodes
        if type(node).__name__ == "Match"
    )
    complexity = 1 + decision_count + boolean_decisions + match_decisions
    density = loop_count / max(1, len(nodes))
    return float(complexity), loop_count, float(density)


def _javascript_complexity(lexemes: list[Lexeme], node_count: int) -> tuple[float, int, float]:
    values = [lexeme.value for lexeme in lexemes]
    loop_count = sum(value in {"for", "while", "do"} for value in values)
    decision_keywords = sum(value in {"if", "case", "catch"} for value in values)
    boolean_decisions = sum(value in {"&&", "||", "??", "?"} for value in values)
    complexity = 1 + decision_keywords + loop_count + boolean_decisions
    density = loop_count / max(1, node_count)
    return float(complexity), loop_count, float(density)


def _threat_breakdown(
    *,
    syntax_valid: bool,
    cyclomatic_complexity: float,
    loop_density: float,
    entropy_index: float,
    obfuscation_index: float,
    injection_index: float,
) -> dict[str, float]:
    complexity_risk = _clip(((cyclomatic_complexity - 1.0) / 24.0) * 100.0)
    loop_density_risk = _clip(loop_density * 400.0)
    return {
        "syntax_risk": 0.0 if syntax_valid else 100.0,
        "complexity_risk": _round(complexity_risk),
        "loop_density_risk": _round(loop_density_risk),
        "entropy_risk": _round(entropy_index),
        "obfuscation_risk": _round(obfuscation_index),
        "injection_risk": _round(injection_index),
    }


def _confidence_index(metrics: AnomalyMetrics) -> float:
    """Estimate analysis confidence separately from content trust.

    A longer, successfully parsed syntax stream gives the algorithm more
    evidence.  Syntax errors reduce confidence but do not prevent a response;
    this is important when the malformed input itself is a threat signal.
    """

    source_factor = min(1.0, math.log1p(metrics.line_count + metrics.token_count) / math.log1p(220))
    node_factor = min(1.0, metrics.syntax_node_count / 80.0)
    confidence = 68.0 + 18.0 * source_factor + 11.0 * node_factor
    if metrics.syntax_valid:
        confidence += 3.0
    else:
        confidence -= 19.0
    if metrics.token_count < 4:
        confidence -= 8.0
    return _round(_clip(confidence))


# ---------------------------------------------------------------------------
# Public mathematical API
# ---------------------------------------------------------------------------


def calculate_trust_score(metrics: AnomalyMetrics | Mapping[str, Any]) -> TrustScore:
    """Calculate a deterministic 0-100 trust score from anomaly metrics.

    The score is a weighted complement of normalized threat signals.  Injection
    evidence receives the largest weight because a short source can still be
    dangerous.  Hard gates prevent a high average score from hiding a clear
    dynamic-execution or payload-decoding signature.
    """

    if isinstance(metrics, AnomalyMetrics):
        breakdown = metrics.threat_breakdown
        syntax_valid = metrics.syntax_valid
        syntax_node_count = metrics.syntax_node_count
        token_count = metrics.token_count
        flags = metrics.anomaly_flags
    else:
        syntax_valid = bool(metrics.get("syntax_valid", True))
        syntax_node_count = int(metrics.get("syntax_node_count", metrics.get("node_count", 0)) or 0)
        token_count = int(metrics.get("token_count", 0) or 0)
        flags = list(metrics.get("anomaly_flags", []))
        provided_breakdown = metrics.get("threat_breakdown")
        if isinstance(provided_breakdown, Mapping):
            breakdown = {str(key): float(value) for key, value in provided_breakdown.items()}
        else:
            complexity = float(metrics.get("cyclomatic_complexity", 1.0) or 1.0)
            loop_density = float(metrics.get("loop_density", 0.0) or 0.0)
            entropy = float(metrics.get("entropy_index", metrics.get("entropy", 0.0)) or 0.0)
            obfuscation = float(metrics.get("obfuscation_index", 0.0) or 0.0)
            injection = float(metrics.get("injection_index", 0.0) or 0.0)
            breakdown = _threat_breakdown(
                syntax_valid=syntax_valid,
                cyclomatic_complexity=complexity,
                loop_density=loop_density,
                entropy_index=entropy,
                obfuscation_index=obfuscation,
                injection_index=injection,
            )

    keys = (
        "syntax_risk",
        "complexity_risk",
        "loop_density_risk",
        "entropy_risk",
        "obfuscation_risk",
        "injection_risk",
    )
    weights = np.asarray([0.12, 0.16, 0.07, 0.18, 0.17, 0.30], dtype=np.float64)
    values = np.asarray([_clip(float(breakdown.get(key, 0.0))) for key in keys], dtype=np.float64)
    risk_score = float(np.dot(values, weights))
    trust_score = _clip(100.0 - risk_score)

    injection_risk = values[-1]
    obfuscation_risk = values[4]
    entropy_risk = values[3]
    # A chained decoder/execution or destructive-shell signal can be
    # malicious even when the source is short and therefore has a modest
    # composite entropy value.  Keep the hard gate below the weighted score so
    # those high-signal combinations cannot average into a benign verdict.
    if (
        injection_risk >= 62.0
        or (injection_risk >= 50.0 and obfuscation_risk >= 42.0)
        or (injection_risk >= 48.0 and entropy_risk >= 72.0)
    ):
        status = MALICIOUS
        trust_score = min(trust_score, 39.99)
    elif not syntax_valid or trust_score < 75.0 or obfuscation_risk >= 78.0 or entropy_risk >= 90.0:
        status = REVIEW_REQUIRED
        trust_score = min(trust_score, 74.99)
    else:
        status = SECURE

    rationale: list[str] = []
    if not syntax_valid:
        rationale.append("Syntax anomalies reduce trust until the source can be parsed cleanly.")
    if injection_risk >= 58:
        rationale.append("Execution, decoder, credential, or sink patterns raised injection risk.")
    if obfuscation_risk >= 65:
        rationale.append("Entropy and opaque-literal signals are consistent with packed or obfuscated code.")
    if breakdown.get("complexity_risk", 0.0) >= 55:
        rationale.append("Decision and control-flow density is above the review threshold.")
    if not rationale:
        rationale.append("No high-confidence malicious signature crossed the decision thresholds.")

    confidence = _round(
        _clip(
            82.0
            + min(10.0, syntax_node_count / 12.0)
            + min(5.0, token_count / 30.0)
            - (18.0 if not syntax_valid else 0.0)
        )
    )
    return TrustScore(
        trust_score=_round(trust_score),
        verification_status=status,
        confidence_index=confidence,
        risk_score=_round(risk_score),
        rationale=rationale,
    )


# Friendly aliases for callers that prefer the names used in product copy.
compute_trust_score = calculate_trust_score
mathematical_trust_score = calculate_trust_score


def analyze_code(
    source_code: str,
    language: str = "auto",
    filename: Optional[str] = None,
) -> InspectionResult:
    """Parse source, calculate anomaly metrics, and produce a trust verdict.

    Syntax errors are intentionally represented in the returned result.  Only
    invalid request shape (empty or oversized input) raises ``ValueError``.
    This lets a security analyst inspect malformed payloads instead of losing
    them to a generic HTTP 500.
    """

    if not isinstance(source_code, str):
        raise ValueError("source_code must be a string")
    if not source_code.strip():
        raise ValueError("source_code cannot be empty")
    if len(source_code) > MAX_SOURCE_CHARS:
        raise ValueError(f"source_code exceeds the {MAX_SOURCE_CHARS:,}-character limit")

    resolved_language = _normalise_language(language, source_code, filename)
    digest = _source_hash(source_code)
    line_count = max(1, source_code.count("\n") + 1)
    logical_lines = _logical_line_count(source_code)
    syntax_errors: list[str] = []
    anomaly_flags: list[str] = []

    if resolved_language == "python":
        lexemes, tokenization_errors = _python_lexemes(source_code)
        syntax_errors.extend(tokenization_errors)
        try:
            tree = ast.parse(source_code, filename=filename or "<veritas-source>", mode="exec")
            _root, syntax_nodes = _python_syntax_nodes(tree)
            syntax_valid = not syntax_errors
            complexity, loop_count, loop_density = _python_complexity(tree)
            syntax_node_types = dict(sorted(Counter(node.kind for node in syntax_nodes).items()))
            parser_log = f"Python AST parse completed with {len(syntax_nodes):,} syntax nodes."
        except (SyntaxError, IndentationError) as exc:
            syntax_valid = False
            line = getattr(exc, "lineno", None) or 1
            column = getattr(exc, "offset", None) or 1
            message = getattr(exc, "msg", str(exc))
            syntax_errors.append(f"Python syntax anomaly at line {line}, column {column}: {message}")
            syntax_nodes = [SyntaxNode("SyntaxError", value=message, line=line, column=column)]
            syntax_node_types = {"SyntaxError": 1}
            complexity = 1.0
            loop_count = 0
            loop_density = 0.0
            parser_log = "Python AST parse failed; lexical metrics were retained for conservative scoring."
    else:
        lexemes, javascript_errors = _javascript_lexemes(source_code)
        syntax_errors.extend(javascript_errors)
        _root, syntax_nodes = _javascript_syntax_nodes(lexemes)
        syntax_valid = not syntax_errors
        complexity, loop_count, loop_density = _javascript_complexity(lexemes, len(syntax_nodes))
        syntax_node_types = dict(sorted(Counter(node.kind for node in syntax_nodes).items()))
        parser_log = f"JavaScript structural parse completed with {len(syntax_nodes):,} syntax nodes."

    token_values = [lexeme.value for lexeme in lexemes if lexeme.kind != "unknown"]
    character_values = [character for character in source_code if not character.isspace()]
    character_entropy = _shannon_entropy(character_values, fixed_cardinality=95)
    token_entropy = _shannon_entropy(token_values)
    entropy_index = _clip(0.65 * character_entropy + 0.35 * token_entropy)
    injection_index, injection_flags = _injection_risk(source_code)
    obfuscation_index, obfuscation_flags = _obfuscation_risk(source_code, lexemes, entropy_index)

    if syntax_errors:
        anomaly_flags.append("syntax_anomaly")
    anomaly_flags.extend(f"injection:{flag}" for flag in injection_flags)
    anomaly_flags.extend(f"obfuscation:{flag}" for flag in obfuscation_flags)
    if complexity >= 12:
        anomaly_flags.append("high_cyclomatic_complexity")
    if loop_density >= 0.20:
        anomaly_flags.append("loop_dense")

    breakdown = _threat_breakdown(
        syntax_valid=syntax_valid,
        cyclomatic_complexity=complexity,
        loop_density=loop_density,
        entropy_index=entropy_index,
        obfuscation_index=obfuscation_index,
        injection_index=injection_index,
    )

    preliminary_metrics = AnomalyMetrics(
        language=resolved_language,
        source_hash=digest,
        syntax_valid=syntax_valid,
        line_count=line_count,
        logical_line_count=logical_lines,
        token_count=len(lexemes),
        syntax_node_count=len(syntax_nodes),
        syntax_node_types=syntax_node_types,
        cyclomatic_complexity=_round(complexity),
        loop_count=int(loop_count),
        loop_density=_round(loop_density, 6),
        character_entropy=_round(character_entropy),
        token_entropy=_round(token_entropy),
        entropy_index=_round(entropy_index),
        obfuscation_index=_round(obfuscation_index),
        injection_index=_round(injection_index),
        threat_breakdown=breakdown,
        anomaly_flags=anomaly_flags,
        syntax_errors=syntax_errors,
        analysis_logs=[],
    )

    trust = calculate_trust_score(preliminary_metrics)
    confidence = max(trust.confidence_index, _confidence_index(preliminary_metrics))
    logs = [
        f"Input fingerprint: sha256:{digest[:16]}…",
        parser_log,
        f"Complexity vector: cyclomatic={preliminary_metrics.cyclomatic_complexity:.2f}; loops={loop_count}; loop density={loop_density:.4f}.",
        f"Entropy vector: character={character_entropy:.2f}; token={token_entropy:.2f}; composite entropy index={entropy_index:.2f}.",
        f"Threat vector: injection={injection_index:.2f}; obfuscation={obfuscation_index:.2f}; weighted risk={trust.risk_score:.2f}.",
    ]
    if syntax_errors:
        logs.append("Syntax anomalies were retained in the evidence log; conservative review scoring applied.")
    else:
        logs.append("Syntax validation passed for the requested language parser.")
    logs.append(f"Trust engine verdict: {trust.verification_status} at {trust.trust_score:.2f}/100.")
    logs.extend(f"Decision note: {reason}" for reason in trust.rationale)

    preliminary_metrics.analysis_logs = logs
    metrics_dict = asdict(preliminary_metrics)
    return InspectionResult(
        analysis_id=digest[:16],
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        language=resolved_language,
        trust_score=trust.trust_score,
        verification_status=trust.verification_status,
        confidence_index=_round(confidence),
        threat_breakdown=breakdown,
        metrics=metrics_dict,
        anomaly_flags=anomaly_flags,
        syntax_errors=syntax_errors,
        analysis_logs=logs,
    )


# ---------------------------------------------------------------------------
# FastAPI adapter
# ---------------------------------------------------------------------------


class InspectCodeRequest(BaseModel):
    """Accepted request body for the inspection endpoint.

    ``code`` is supported as a concise alias for clients that already use that
    field name.  ``source_code`` takes precedence if both are supplied.
    """

    source_code: Optional[str] = Field(default=None, description="Python or JavaScript source to inspect")
    code: Optional[str] = Field(default=None, description="Alias for source_code")
    language: str = Field(default="auto", description="python, javascript, or auto")
    filename: Optional[str] = Field(default=None, description="Optional filename used by auto language detection")


app = FastAPI(
    title="Veritas Inspector Analysis Core",
    version="1.0.0",
    description="Deterministic AST and entropy-based code inspection service.",
)
# The combined service also hosts /api/v1/filter-threat, so the body limit must
# cover file uploads rather than source-only inspection.
install_api_protections(app, max_body_bytes=26 * 1024 * 1024)


@app.get("/health")
def health() -> dict[str, str]:
    """Small liveness endpoint for orchestration and smoke checks."""

    return {"status": "ok", "service": "veritas-inspector-analysis-core"}


@app.post("/api/v1/inspect-code")
def inspect_code(payload: InspectCodeRequest) -> dict[str, Any]:
    """Inspect source code and return a structured mathematical verdict."""

    source_code = payload.source_code if payload.source_code is not None else payload.code
    if source_code is None:
        raise HTTPException(status_code=422, detail="Provide source_code (or code) in the request body")

    try:
        result = analyze_code(source_code, payload.language, payload.filename)
    except UnsupportedLanguageError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - final API safety net
        # Do not expose implementation details to API consumers.  Syntax
        # anomalies are handled above and should never reach this branch.
        raise HTTPException(status_code=500, detail="Code inspection failed safely") from exc

    return result.to_dict()


# The threat-filtering module is kept separate for reuse, while its router is
# mounted here so the original backend entry point exposes both API surfaces.
from threat_filter_core import threat_router  # noqa: E402

app.include_router(threat_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend_core:app", host="0.0.0.0", port=8000, reload=False)
