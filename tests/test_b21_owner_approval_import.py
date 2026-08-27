from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_b21_owner_directive_import_is_bounded() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_b21_owner_approval_import.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: B2.1 owner-directive import is bounded and fail-closed" in result.stdout
