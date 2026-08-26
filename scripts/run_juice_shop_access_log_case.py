"""Run the approved Juice Shop access-log semantic proof on loopback only."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from urllib.parse import urljoin

from run_juice_shop_p10_full import (
    ORIGIN,
    build_browser_executor,
    record_proof_result,
    scope,
    semantic_finding,
)

from webpent.benchmark.juice_shop_target_adapter import JUICE_SHOP_TARGET_REGISTRATION
from webpent.shared.control_plane_runtime import BrowserActionAdapter
from webpent.shared.control_plane_spine import build_control_plane_runtime
from webpent.shared.playwright_adapter import EphemeralProbeStore, PlaywrightBrowserHandler
from webpent.shared.semantic_proof_runner import SemanticProofRunner
from webpent.shared.target_adapters import TargetAdapterRegistry

CASE_ID = "juice.access_log_disclosure.v1"


def normalized_origin(value: str) -> str:
    if value != ORIGIN:
        raise ValueError("only_loopback_juice_shop_origin_allowed")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", default=ORIGIN)
    args = parser.parse_args()

    target_origin = normalized_origin(args.origin)
    target_registry = TargetAdapterRegistry()
    target_registry.register(JUICE_SHOP_TARGET_REGISTRATION)
    target_adapter = target_registry.require_for_origin(target_origin).adapter
    case = target_adapter.case(CASE_ID)
    if case is None or case.semantic_profile is None:
        raise SystemExit("access_log_case_or_profile_not_registered")

    run_id = str(args.run_id)
    engagement_id = f"juice-access-log-{run_id}"
    profile_root = Path("/tmp") / f"webpent-access-log-{run_id}"
    shutil.rmtree(profile_root, ignore_errors=True)
    profile_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    current_scope = scope(engagement_id)
    probe_store = EphemeralProbeStore()
    handler = PlaywrightBrowserHandler(
        target_origin=target_origin,
        engagement_id=engagement_id,
        profile_root=profile_root / "browser-profile",
        headless=True,
        browser_timeout_ms=15_000,
        probe_resolver=probe_store.resolve,
        semantic_profile_registry=target_adapter.semantic_profiles,
        workflow_allowlist=target_adapter.workflow_ids(),
        workflow_executors=target_adapter.workflow_executors(),
    )
    adapter = BrowserActionAdapter(
        handler,
        probe_registrar=probe_store.put,
        probe_cleaner=probe_store.clear,
    )
    control_plane = build_control_plane_runtime(
        engagement_id=engagement_id,
        scope=current_scope,
        executor=build_browser_executor(target_origin, handler),
        profile_root=str(profile_root / "runtime-profile"),
    )
    session = control_plane.session_manager.create_session(
        engagement_id=engagement_id,
        profile_ref="juice-access-log-case",
        authenticated_origins=(),
        cookie_fingerprint="sha256:" + "0" * 64,
    )

    target_url = urljoin(target_origin + "/", case.path.lstrip("/"))
    proof_runner = SemanticProofRunner(
        replay_engine=control_plane.replay_engine,
        adapter=adapter,
        session=session,
        scope=current_scope,
        engagement_id=engagement_id,
        semantic_profile=case.semantic_profile,
        semantic_profiles=target_adapter.semantic_profiles,
        validator_id="juice-shop-access-log-semantic-adapter",
        validator_version="1",
    )
    proof_result = proof_runner.run(
        semantic_finding(CASE_ID, target_url),
        baseline_url=urljoin(target_origin + "/", ""),
        candidate_url=target_url,
        negative_control_url=urljoin(
            target_origin + "/", "p10-negative-control-not-found"
        ),
        scope_context={
            "target_origin": target_origin,
            "target_path": case.path,
            "scope_bound": True,
        },
        identity_context={
            "mode": "anonymous",
            "session_ref": session.session_id,
            "credentials_retained": False,
        },
        replay_metadata={
            "case_id": CASE_ID,
            "oracle_id": case.oracle_id,
            "runner": "juice-shop-access-log-case.v1",
        },
    )

    observations: dict[str, object] = {}
    statuses: dict[str, str] = {}
    proof_states: dict[str, dict[str, object]] = {}
    proof_bundles: dict[str, dict[str, object]] = {}
    record_proof_result(
        CASE_ID,
        proof_result,
        observations=observations,
        statuses=statuses,
        proof_states=proof_states,
        proof_bundles=proof_bundles,
    )
    summary = {
        "schema_version": "juice_shop.access_log_case_run.v1",
        "run_id": run_id,
        "engagement_id": engagement_id,
        "target": target_origin,
        "case_id": CASE_ID,
        "case_path": case.path,
        "semantic_profile": case.semantic_profile,
        "status": statuses.get(CASE_ID, "blocked_by_precondition"),
        "proof_state": proof_states.get(CASE_ID, {}),
        "observations": observations,
        "proof_bundle": proof_bundles.get(CASE_ID, {}),
        "verification_passed": proof_result.passed,
        "verification_reason": proof_result.reason,
        "raw_data_retained": False,
        "raw_data_printed": False,
        "network_policy": "authorized_loopback_only",
        "mutation_policy": "no_state_mutation",
        "qualification_claim": "none",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "case_id": CASE_ID,
                "status": summary["status"],
                "verification_passed": proof_result.passed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
