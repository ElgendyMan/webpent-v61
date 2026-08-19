"""Run reproducible local quality gates for the VIP release candidate."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "docs" / "vip_quality_gate.json"
PYTHON = sys.executable
_LOCAL_RUFF = Path(PYTHON).with_name("ruff")
RUFF = str(_LOCAL_RUFF) if _LOCAL_RUFF.is_file() else (shutil.which("ruff") or "ruff")
PYTEST = [PYTHON, "-m", "pytest", "-q"]

VIP_FILES = [
    "src/webpent/models/campaigns.py",
    "src/webpent/models/application_intent.py",
    "src/webpent/models/evidence_ledger.py",
    "src/webpent/models/proof_engine.py",
    "src/webpent/models/surface_graph.py",
    "src/webpent/models/surface_security.py",
    "src/webpent/models/workflow_replay.py",
    "src/webpent/models/workflows.py",
    "src/webpent/shared/application_intent.py",
    "src/webpent/shared/application_intent_graph.py",
    "src/webpent/shared/campaign_planner.py",
    "src/webpent/shared/evidence_ledger.py",
    "src/webpent/shared/proof_engine.py",
    "src/webpent/shared/surface_evidence_graph.py",
    "src/webpent/shared/surface_security.py",
    "src/webpent/shared/validator_plugins.py",
    "src/webpent/shared/offline_validator_fixtures.py",
    "src/webpent/shared/workflow_replay.py",
    "src/webpent/shared/workflow_understanding.py",
    "src/webpent/shared/adaptive_hunt.py",
    "src/webpent/state/initial_state.py",
    "src/webpent/state/state.py",
    "src/webpent/agents/validator/agent.py",
    "scripts/capture_vip_baseline.py",
    "scripts/run_vip_quality_gate.py",
    "scripts/run_waptlab_regression.py",
    "tests/test_vip_application_intent_graph.py",
    "tests/test_vip_baseline.py",
    "tests/test_vip_campaign_planner.py",
    "tests/test_vip_proof_engine.py",
    "tests/test_vip_shared_reauth_vault.py",
    "tests/test_vip_surface_intent.py",
    "tests/test_vip_validator_plugins.py",
    "tests/test_vip_offline_validator_fixtures.py",
    "tests/test_vip_waptlab_regression.py",
    "tests/test_vip_workflow_replay.py",
]


def _run(name: str, command: list[str], *, timeout: int = 300) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": "src"},
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip().splitlines()
        return {
            "name": name,
            "command": command,
            "passed": completed.returncode == 0,
            "returncode": completed.returncode,
            "tail": output[-12:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": name,
            "command": command,
            "passed": False,
            "returncode": None,
            "tail": [f"{type(exc).__name__}: {exc}"],
        }


def _artifact_safety() -> dict[str, Any]:
    path = PROJECT_ROOT / "docs" / "waptlab_regression.json"
    if not path.is_file():
        return {"passed": False, "reason": "missing docs/waptlab_regression.json"}
    payload = json.loads(path.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    passed = (
        payload.get("campaign_count") == 20
        and payload.get("target_contacted") is False
        and payload.get("waptlab_modified") is False
        and sum(summary.values()) == 20
        and summary.get("inconclusive") == 13
        and summary.get("missing-validator") == 7
    )
    return {
        "passed": passed,
        "campaign_count": payload.get("campaign_count"),
        "summary": summary,
        "target_contacted": payload.get("target_contacted"),
        "waptlab_modified": payload.get("waptlab_modified"),
    }


def main() -> int:
    checks = [
        _run("compileall", [PYTHON, "-m", "compileall", "-q", "src", "scripts"]),
        _run("ruff", [RUFF, "check", *VIP_FILES]),
        _run("pytest", [*PYTEST], timeout=360),
        _run(
            "test-function-count",
            [PYTHON, "scripts/verify_test_count.py", "--minimum", "498"],
            timeout=60,
        ),
    ]
    safety = _artifact_safety()
    passed = all(check["passed"] for check in checks) and safety["passed"]
    report = {
        "schema_version": "vip-quality-gate-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v60",
        "passed": passed,
        "checks": checks,
        "waptlab_artifact_safety": safety,
        "known_blockers": [
            "worker critical-path coverage remains 23% versus the 85% target",
            "LangChain/LangGraph advisory set remains documented in pip-audit-production.json",
            "WAPTLab regression is local contract-only; no campaign is confirmed by this gate",
        ],
    }
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"passed": passed, "output": str(OUTPUT_PATH)}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
