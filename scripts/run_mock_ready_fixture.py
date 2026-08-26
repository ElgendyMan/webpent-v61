"""Run the opt-in Mock ready fixture through the generic lifecycle runner.

This is a local synthetic fixture check only. It does not start a server, perform
network I/O, mutate state, or qualify Juice Shop/P10/VIP.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from webpent.adapters.mock_target.adapter import (
    MOCK_TARGET_ADAPTER,
    MOCK_TARGET_REGISTRATION,
    MockTargetAdapter,
    build_mock_target_registration,
)
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import LifecycleAuthorization, LifecycleRunContext

_REPO = Path(__file__).resolve().parents[1]
_ORIGIN = "http://127.0.0.1:4200"
_ENGAGEMENT = "offline-mock-fn-001-ready-rerun"


def _authorization() -> LifecycleAuthorization:
    return LifecycleAuthorization(
        authorized=True,
        engagement_id=_ENGAGEMENT,
        allowed_origin=_ORIGIN,
        satisfied_requirements=("explicit_fixture_authorization", "loopback_origin"),
    )


def _context(registration: Any, case_id: str, run_id: str) -> LifecycleRunContext:
    return LifecycleRunContext(
        run_id=run_id,
        target_id=str(registration.adapter.target_id),
        case_id=case_id,
        engagement_id=_ENGAGEMENT,
    )


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _safe_result(result: Any) -> dict[str, Any]:
    return result.as_dict()


def main() -> None:
    default_case = MOCK_TARGET_ADAPTER.case_definition()
    default_result = GenericCaseRunner.execute_case(
        MOCK_TARGET_REGISTRATION,
        default_case,
        _authorization(),
        _context(MOCK_TARGET_REGISTRATION, default_case.case_id, "mock-ready-default-control-001"),
    )

    ready_adapter = MockTargetAdapter(ready=True)
    ready_registration = build_mock_target_registration(ready_adapter)
    ready_case = ready_adapter.case_definition()
    ready_run_id = "mock-ready-postfix-001"
    ready_result = GenericCaseRunner.execute_case(
        ready_registration,
        ready_case,
        _authorization(),
        _context(ready_registration, ready_case.case_id, ready_run_id),
    )

    verification = ready_adapter._last_verification
    if verification is None or verification.proof_bundle is None:
        raise RuntimeError("ready_fixture_verification_missing")
    bundle = verification.proof_bundle
    evidence = verification.evidence
    seal_ok = bundle.verify_seal()
    replay_ok = bundle.replay(
        [evidence["baseline"], evidence["candidate"], evidence["negative_control"]],
        evidence["negative_control"],
        replay_context=evidence["replay_context"],
    )
    if not seal_ok or not replay_ok:
        raise RuntimeError(f"ready_fixture_proof_invalid:seal={seal_ok}:replay={replay_ok}")

    artifact = {
        "artifact_id": "mock-ready-fixture-postfix-v1",
        "run_id": ready_run_id,
        "commit_sha": _git_head(),
        "scope": "mock-target-fixture-only",
        "qualification": {
            "p10": "NOT_QUALIFIED",
            "p9": "NOT_QUALIFIED",
            "vip": "NOT_QUALIFIED",
            "synthetic_fixture_only": True,
        },
        "safety": {
            "network_io": False,
            "state_mutation": False,
            "raw_response_bodies_saved": False,
            "credentials_or_cookies_saved": False,
        },
        "default_control": {
            "target_id": MOCK_TARGET_REGISTRATION.target_id,
            "status": default_result.status,
            "reason": default_result.reason,
            "proof_bundle_ref": default_result.proof_bundle_ref,
            "negative_control_ref": default_result.negative_control_ref,
            "serialized_result": _safe_result(default_result),
        },
        "ready_result": {
            "target_id": ready_registration.target_id,
            "case_id": ready_case.case_id,
            "status": ready_result.status,
            "reason": ready_result.reason,
            "proof_bundle_ref": ready_result.proof_bundle_ref,
            "negative_control_ref": ready_result.negative_control_ref,
            "serialized_result": _safe_result(ready_result),
        },
        "verification": {
            "passed": verification.passed,
            "reason": verification.reason,
            "proof_bundle_id": bundle.bundle_id,
            "proof_bundle_sealed": seal_ok,
            "replay_verified": replay_ok,
            "target_backed": bundle.target_backed,
            "negative_control_independent": bundle.negative_control_independent,
            "target_fingerprint": verification.evidence["target_fingerprint"],
            "replay_context": verification.evidence["replay_context"],
            "observation_roles": [
                verification.evidence["baseline"]["observation_role"],
                verification.evidence["candidate"]["observation_role"],
                verification.evidence["negative_control"]["observation_role"],
            ],
            "request_digests": [
                verification.evidence["candidate"]["request_digest"],
                verification.evidence["negative_control"]["request_digest"],
            ],
            "proof_bundle": bundle.model_dump(mode="json"),
        },
    }
    output = _REPO / "audit" / "mock_ready_fixture_postfix_v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    print(json.dumps({
        "default_status": default_result.status,
        "ready_status": ready_result.status,
        "proof_bundle_id": bundle.bundle_id,
        "proof_bundle_sealed": seal_ok,
        "replay_verified": replay_ok,
    }, sort_keys=True))


if __name__ == "__main__":
    main()


__all__ = ["main"]
