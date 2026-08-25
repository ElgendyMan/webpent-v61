"""Run reproducible local quality and release-security gates."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS = PROJECT_ROOT / "docs"
OUTPUT_PATH = DOCS / "vip_quality_gate.json"
PYTHON = sys.executable
BUNDLED_BBSCOUT_ROOT = PROJECT_ROOT / "integrations" / "bbscout" / "src"

def _local_or_path(tool: str) -> str:
    """Prefer the executable installed beside the interpreter running the gate."""
    local = Path(PYTHON).with_name(tool)
    return str(local) if local.is_file() else (shutil.which(tool) or tool)


RUFF = _local_or_path("ruff")
BANDIT = _local_or_path("bandit")
PIP_AUDIT = _local_or_path("pip-audit")
UV = shutil.which("uv")
PYTEST = [PYTHON, "-m", "pytest", "-q"]


def _bundled_bbscout_source() -> Path | None:
    """Return the reviewed, reproducible bbscout source bundled with this checkout."""
    package_dir = BUNDLED_BBSCOUT_ROOT / "bbscout"
    if (package_dir / "__init__.py").is_file():
        return BUNDLED_BBSCOUT_ROOT
    return None


def _configured_bbscout_source() -> Path | None:
    """Return a reviewed external bbscout source root when explicitly configured."""
    configured = os.environ.get("BBSCOUT_SOURCE_ROOT", "").strip()
    if not configured:
        return None
    root = Path(configured).expanduser().resolve()
    package_dir = root / "bbscout"
    if (package_dir / "__init__.py").is_file():
        return root
    return None


def _bbscout_integration_check() -> dict[str, Any]:
    """Report bbscout availability without importing or executing source code."""
    external_root = _configured_bbscout_source()
    if external_root is not None:
        return {
            "name": "bbscout-integration-source",
            "passed": True,
            "returncode": 0,
            "status": "external-reviewed-source",
            "required_for_full_gate": True,
            "source_root": "external:BBSCOUT_SOURCE_ROOT",
            "reason": "bbscout source is explicitly configured outside the WebPent checkout",
        }
    bundled_root = _bundled_bbscout_source()
    if bundled_root is not None:
        return {
            "name": "bbscout-integration-source",
            "passed": True,
            "returncode": 0,
            "status": "bundled-reviewed-source",
            "required_for_full_gate": True,
            "source_root": "integrations/bbscout/src",
            "reason": "reviewed bbscout source is bundled in the checkout",
        }
    try:
        available = importlib.util.find_spec("bbscout") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        available = False
    if available:
        return {
            "name": "bbscout-integration-source",
            "passed": True,
            "returncode": 0,
            "status": "available",
            "required_for_full_gate": True,
            "reason": "bbscout source is importable",
        }
    return {
        "name": "bbscout-integration-source",
        "passed": False,
        "returncode": 1,
        "status": "blocked",
        "required_for_full_gate": True,
        "reason": "bbscout source tree is unavailable in this checkout",
    }


def _gate_pythonpath() -> str:
    """Build the subprocess path with optional external bbscout source."""
    parts = [str(PROJECT_ROOT / "src")]
    external_root = _configured_bbscout_source()
    if external_root is not None:
        parts.append(str(external_root))
    bundled_root = _bundled_bbscout_source()
    if bundled_root is not None and bundled_root not in [Path(part) for part in parts]:
        parts.append(str(bundled_root))
    inherited = os.environ.get("PYTHONPATH", "")
    if inherited:
        parts.append(inherited)
    return os.pathsep.join(parts)


RUFF_PATHS = ["src", "tests", "scripts"]


def _run(name: str, command: list[str], *, timeout: int = 300) -> dict[str, Any]:
    """Run one gate and retain bounded output for machine-readable review."""
    try:
        pythonpath = _gate_pythonpath()
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": pythonpath},
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
    path = DOCS / "waptlab_regression.json"
    if not path.is_file():
        return {"passed": False, "reason": "missing docs/waptlab_regression.json"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"passed": False, "reason": f"invalid regression artifact: {exc}"}
    summary = payload.get("summary", {})
    summary_is_complete = (
        isinstance(summary, dict)
        and bool(summary)
        and all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in summary.values()
        )
        and sum(summary.values()) == 20
    )
    passed = (
        payload.get("campaign_count") == 20
        and payload.get("target_contacted") is False
        and payload.get("waptlab_modified") is False
        and summary_is_complete
    )
    return {
        "passed": passed,
        "campaign_count": payload.get("campaign_count"),
        "summary": summary,
        "target_contacted": payload.get("target_contacted"),
        "waptlab_modified": payload.get("waptlab_modified"),
    }


def _dependency_input() -> tuple[list[str], str]:
    """Prefer a lock-derived requirement export and fall back to the audit file."""
    output = PROJECT_ROOT / "docs" / "requirements-audit-release.txt"
    if UV:
        result = _run(
            "export-locked-requirements",
            [
                UV,
                "export",
                "--locked",
                "--all-groups",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--output-file",
                str(output),
            ],
            timeout=120,
        )
        if result["passed"] and output.is_file():
            return [str(output)], "uv-exported-lock"
    fallback = PROJECT_ROOT / "requirements-audit-v63.txt"
    return [str(fallback)], "requirements-audit-v63"


def _preflight_contract() -> dict[str, Any]:
    path = DOCS / "preflight_report.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        posture = payload.get("posture", {})
        passed = (
            payload.get("schema_version") == "webpent-preflight-v1"
            and payload.get("host_evaluated") == "127.0.0.1"
            and posture.get("state") in {
                "PASS",
                "READY_WITH_WARNING",
                "DEGRADED",
            }
            and posture.get("fail_closed") is True
        )
        return {
            "name": "preflight-report-contract",
            "command": [str(path)],
            "passed": passed,
            "returncode": 0 if passed else 1,
            "tail": [] if passed else ["invalid preflight posture artifact"],
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "name": "preflight-report-contract",
            "command": [str(path)],
            "passed": False,
            "returncode": None,
            "tail": [f"{type(exc).__name__}: {exc}"],
        }


def _g02_checks() -> list[dict[str, Any]]:
    """Run deterministic G-02 regeneration and independent runtime checks."""
    return [
        _run(
            "g02-artifact-regeneration",
            [PYTHON, "scripts/scan_direct_io.py"],
            timeout=60,
        ),
        _run(
            "g02-static-runtime-contract",
            [PYTHON, "scripts/check_g02_runtime.py"],
            timeout=60,
        ),
        _run(
            "g02-precommit-contract",
            [PYTHON, "scripts/check_g02_precommit.py"],
            timeout=60,
        ),
    ]


def _artifact_check(
    name: str,
    path: Path,
    predicate: Any,
    missing_reason: str,
) -> dict[str, Any]:
    """Evaluate a JSON qualification artifact without treating it as proof by itself."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "name": name,
            "command": [str(path)],
            "passed": False,
            "returncode": 1,
            "tail": [f"{type(exc).__name__}: {exc}"],
        }
    try:
        passed, reason = predicate(payload)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        passed, reason = False, f"invalid artifact shape: {type(exc).__name__}"
    return {
        "name": name,
        "command": [str(path)],
        "passed": bool(passed),
        "returncode": 0 if passed else 1,
        "tail": [] if passed else [reason or missing_reason],
    }


def _p8_live_proof_check() -> dict[str, Any]:
    path = DOCS / "juice_shop_qualification_report.json"

    def predicate(payload: dict[str, Any]) -> tuple[bool, str]:
        runs = payload.get("runs")
        if not isinstance(runs, list):
            return False, "P8 live proof runs are missing"
        valid = [
            run
            for run in runs
            if isinstance(run, dict)
            and run.get("passed") is True
            and run.get("verifier_passed") is True
            and run.get("central_store_put") is True
            and run.get("central_verify_seal") is True
            and run.get("central_replay") is True
            and run.get("proof_bundle_sealed") is True
            and run.get("replay_status") == "passed"
            and run.get("target_backed_all") is True
            and run.get("replayable_all") is True
            and run.get("raw_response_bodies_saved") is False
        ]
        if not valid:
            return False, "no target-backed sealed and centrally replayed P8 run"
        return True, ""

    return _artifact_check(
        "p8-live-proof-artifact",
        path,
        predicate,
        "P8 live proof artifact is missing",
    )


def _p9_distributed_check() -> dict[str, Any]:
    path = DOCS / "p9_distributed_runtime_evidence.json"

    def predicate(payload: dict[str, Any]) -> tuple[bool, str]:
        checks = payload.get("qualification_checks")
        if not isinstance(checks, dict):
            return False, "P9 qualification checks are missing"
        required = {
            "docker_health",
            "redis_health",
            "celery_worker_health",
            "multi_worker_queue_distribution",
            "multi_worker_lease_contention",
            "crash_restart_recovery",
            "checkpoint_resume",
            "killed_worker_redelivery",
            "cross_process_idempotency",
            "broker_idempotency",
            "retry_exhaustion",
            "dlq_projection",
            "secrets_externalized",
            "tls_enforced",
            "logs_redacted",
            "retention_policy_verified",
            "backup_restore",
            "target_unchanged",
        }
        missing = sorted(name for name in required if checks.get(name) is not True)
        if missing:
            return False, "P9 required checks incomplete: " + ", ".join(missing)
        return True, ""

    return _artifact_check(
        "p9-distributed-qualification-artifact",
        path,
        predicate,
        "P9 distributed qualification artifact is missing",
    )


def _p10_benchmark_check() -> dict[str, Any]:
    path = DOCS / "juice_shop_qualification_report.json"

    def predicate(payload: dict[str, Any]) -> tuple[bool, str]:
        gate = payload.get("gate")
        metrics = payload.get("metrics")
        ground_truth = payload.get("ground_truth")
        if not isinstance(gate, dict) or not isinstance(metrics, dict):
            return False, "P10 benchmark artifact is missing gate or metrics"
        if gate.get("p10_passed") is not True:
            reasons = gate.get("blocking_reasons") or ["P10 gate is not passed"]
            return False, "P10 benchmark not qualified: " + "; ".join(map(str, reasons))
        if metrics.get("run_count", 0) < 3 or metrics.get("successful_proof_runs", 0) < 3:
            return False, "P10 requires at least three successful isolated proof runs"
        if (
            not isinstance(ground_truth, dict)
            or ground_truth.get("case_mapping_status") != "approved"
        ):
            return False, "P10 ground-truth case mapping is not approved"
        if any(metrics.get(key) is None for key in ("precision", "recall", "class_coverage")):
            return False, "P10 precision, recall, and class coverage are incomplete"
        return True, ""

    return _artifact_check(
        "p10-juice-shop-benchmark-artifact",
        path,
        predicate,
        "P10 benchmark artifact is missing",
    )


def _qualification_checks() -> list[dict[str, Any]]:
    """Build and validate local qualification artifacts without live claims."""
    checks = [
        _run(
            "preflight-report",
            [PYTHON, "scripts/build_preflight_report.py", "--host", "127.0.0.1"],
            timeout=60,
        ),
        _run(
            "capability-report",
            [PYTHON, "scripts/build_capability_report.py"],
            timeout=60,
        ),
        _run(
            "mock-qualification-report",
            [PYTHON, "scripts/build_mock_qualification_report.py"],
            timeout=60,
        ),
    ]
    capability_path = DOCS / "capability_report.json"
    qualification_path = DOCS / "waptlab_qualification_report.json"
    try:
        capability = json.loads(capability_path.read_text(encoding="utf-8"))
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        capability_passed = (
            capability.get("catalog_count") == 20
            and capability.get("live_qualification") is False
            and "missing-validator" not in capability.get("validator_status_counts", {})
        )
        qualification_passed = (
            qualification.get("run_count") == 3
            and qualification.get("stable_campaign_signatures") is True
            and qualification.get("live_qualification") is False
            and qualification.get("target_contacted") is False
            and qualification.get("waptlab_modified") is False
        )
    except (OSError, json.JSONDecodeError) as exc:
        capability_passed = False
        qualification_passed = False
        checks.append(
            {
                "name": "qualification-artifact-read",
                "command": [],
                "passed": False,
                "returncode": None,
                "tail": [f"{type(exc).__name__}: {exc}"],
            }
        )
    checks.append(_preflight_contract())
    checks.extend([_p8_live_proof_check(), _p9_distributed_check(), _p10_benchmark_check()])
    checks.extend(
        [
            {
                "name": "capability-report-contract",
                "command": [str(capability_path)],
                "passed": capability_passed,
                "returncode": 0 if capability_passed else 1,
                "tail": [],
            },
            {
                "name": "mock-qualification-contract",
                "command": [str(qualification_path)],
                "passed": qualification_passed,
                "returncode": 0 if qualification_passed else 1,
                "tail": [],
            },
        ]
    )
    return checks


def _security_checks() -> list[dict[str, Any]]:
    """Run high-severity Bandit and strict dependency/SBOM checks."""
    bandit_json = DOCS / "bandit_release.json"
    bandit_check = _run(
        "bandit-high-severity",
        [
            BANDIT,
            "-q",
            "-r",
            "src/webpent",
            "-x",
            "tests",
            "-lll",
            "-f",
            "json",
            "-o",
            str(bandit_json),
        ],
        timeout=180,
    )
    requirement_args, requirement_source = _dependency_input()
    requirement_path = requirement_args[0]
    sbom_path = DOCS / "sbom.cdx.json"
    audit_json = DOCS / "pip_audit_release.json"
    sbom_check = _run(
        "pip-audit-sbom",
        [
            PIP_AUDIT,
            "--strict",
            "--timeout",
            "15",
            "--requirement",
            requirement_path,
            "--format",
            "cyclonedx-json",
            "--output",
            str(sbom_path),
        ],
        timeout=240,
    )
    audit_check = _run(
        "pip-audit-strict",
        [
            PIP_AUDIT,
            "--strict",
            "--timeout",
            "15",
            "--requirement",
            requirement_path,
            "--format",
            "json",
            "--output",
            str(audit_json),
        ],
        timeout=240,
    )
    secret_check = _run(
        "tracked-secret-scan",
        [PYTHON, "scripts/check_tracked_secrets.py"],
        timeout=60,
    )
    for check in (bandit_check, sbom_check, audit_check):
        check["requirement_source"] = requirement_source
    return [bandit_check, sbom_check, audit_check, secret_check]


def _build_gate_report(checks: list[dict[str, Any]], safety: dict[str, Any]) -> dict[str, Any]:
    """Build a report from checks without mutating release artifacts."""
    hard_checks_passed = all(check["passed"] for check in checks) and safety["passed"]
    blockers: list[str] = []
    check_by_name = {check["name"]: check for check in checks}
    for name, message in (
        (
            "p8-live-proof-artifact",
            "P8 has no target-backed sealed and centrally replayed live proof",
        ),
        (
            "p9-distributed-qualification-artifact",
            "P9 distributed qualification is incomplete",
        ),
        (
            "p10-juice-shop-benchmark-artifact",
            "P10 Juice Shop benchmark is incomplete or not qualified",
        ),
    ):
        if not check_by_name.get(name, {}).get("passed", False):
            blockers.append(message)
    if not check_by_name.get("pip-audit-strict", {}).get("passed", False):
        blockers.append(
            "pip-audit strict did not pass; dependency advisories remain a release blocker"
        )
    if not check_by_name.get("bandit-high-severity", {}).get("passed", False):
        blockers.append(
            "Bandit high-severity gate did not pass or did not produce an artifact"
        )
    if not check_by_name.get("release-manifest", {}).get("passed", False):
        blockers.append("release manifest could not be generated")
    bbscout_check = check_by_name.get("bbscout-integration-source", {})
    if not bbscout_check.get("passed", False):
        blockers.append(
            "bbscout source tree is unavailable; optional target-package integration is blocked"
        )
    return {
        "schema_version": "vip-quality-gate-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v72",
        "hard_checks_passed": hard_checks_passed,
        "passed": hard_checks_passed and not blockers,
        "checks": checks,
        "waptlab_artifact_safety": safety,
        "security_artifacts": {
            "bandit": "docs/bandit_release.json",
            "pip_audit": "docs/pip_audit_release.json",
            "sbom": "docs/sbom.cdx.json",
        },
        "known_blockers": blockers,
    }


def _write_gate_report(report: dict[str, Any]) -> None:
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    # Regenerate deterministic G-02 artifacts before pytest: the tests intentionally
    # reject stale inventories, so the gate must establish the current artifact first.
    checks = [
        _run("compileall", [PYTHON, "-m", "compileall", "-q", "src", "scripts"]),
        _run("ruff", [RUFF, "check", *RUFF_PATHS]),
    ]
    checks.extend(_g02_checks())
    checks.extend(
        [
            _run("pytest", [*PYTEST], timeout=420),
            _bbscout_integration_check(),
            _run(
                "test-function-count",
                # Static function-preservation guard; pytest's passed count
                # is checked above.
                [PYTHON, "scripts/verify_test_count.py", "--minimum", "818"],
                timeout=60,
            ),
        ]
    )
    checks.extend(_qualification_checks())
    checks.extend(_security_checks())
    safety = _artifact_safety()

    # The manifest reads vip_quality_gate.json. Write a provisional report before
    # building it, then write the final report with the successful manifest check,
    # and refresh the manifest once more so its hashes describe the final report.
    provisional_checks = [
        *checks,
        {
            "name": "release-manifest",
            "passed": False,
            "returncode": None,
            "stdout_tail": "bootstrap: manifest generation pending",
            "stderr_tail": "",
        },
    ]
    _write_gate_report(_build_gate_report(provisional_checks, safety))
    manifest_check = _run(
        "release-manifest",
        [PYTHON, "scripts/build_release_manifest.py"],
        timeout=60,
    )
    checks.append(manifest_check)
    report = _build_gate_report(checks, safety)
    _write_gate_report(report)
    refresh_check = _run(
        "release-manifest-refresh",
        [PYTHON, "scripts/build_release_manifest.py"],
        timeout=60,
    )
    if not refresh_check["passed"]:
        report["known_blockers"].append("release manifest refresh could not be generated")
        report["passed"] = False
        report["hard_checks_passed"] = False
        _write_gate_report(report)

    # Generation alone is not an integrity check. Verify the final manifest
    # against the current tree after the last refresh; this remains offline-only.
    manifest_verify = _run(
        "release-manifest-verify",
        [
            PYTHON,
            "scripts/verify_release_artifacts.py",
            "--repo",
            str(PROJECT_ROOT),
            "--manifest",
            str(DOCS / "release_manifest.json"),
        ],
        timeout=60,
    )
    if not manifest_verify["passed"]:
        report["known_blockers"].append(
            "release manifest does not verify against the final source tree"
        )
        report["passed"] = False
        report["hard_checks_passed"] = False
        _write_gate_report(report)
    print(
        json.dumps(
            {
                "passed": report["passed"] and manifest_verify["passed"],
                "release_manifest_verify": manifest_verify["passed"],
                "output": str(OUTPUT_PATH),
            },
            sort_keys=True,
        )
    )
    return 0 if report["passed"] and manifest_verify["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
