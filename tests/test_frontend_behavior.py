"""Behavioral frontend tests (object-URL lifecycle + health polling) run in Node.

The suite lives in tests/test_app_behavior.js and executes the real app.js
against a minimal DOM/timer/network harness (tests/frontend_harness.js).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_app_behavior_node_suite() -> None:
    script = ROOT / "tests" / "test_app_behavior.js"
    completed = subprocess.run(
        ["node", str(script)],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "app.js behavior tests passed" in completed.stdout
