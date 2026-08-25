"""Run one bounded, redacted Juice Shop P10 live pass.

This harness executes only the approved local case set through the existing
Playwright control plane. It records observations, never promotes findings, and
never creates a ProofBundle unless a real causal/replay adapter is added.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from webpent.benchmark.juice_shop_safe_cases import get_juice_shop_safe_case
from webpent.benchmark.p10_review import validate_mapping_review
from webpent.shared.control_plane import (
    BrowserActionRequest,
    BrowserSessionRef,
    compile_scope,
    evaluate_scope,
)
from webpent.shared.control_plane_runtime import BrowserActionAdapter, BrowserSessionManager
from webpent.shared.playwright_adapter import EphemeralProbeStore, PlaywrightBrowserHandler

ORIGIN = "http://127.0.0.1:3000"
EXPECTED_MAPPING = "sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5"
EXPECTED_ORACLE = "sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c"
NEUTRAL_PROBE = "p10-neutral-observation"


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def origin(value: str) -> str:
    parsed = urlsplit(value)
    normalized = f"{parsed.scheme.lower()}://{parsed.hostname}:{parsed.port or 80}"
    if normalized != ORIGIN:
        raise ValueError("only_loopback_juice_shop_origin_allowed")
    return normalized


def scope(engagement_id: str):
    return compile_scope(
        engagement_id=engagement_id,
        root_domains=(ORIGIN,),
        allowed_schemes=("http",),
        allowed_ports=(3000,),
        path_rules=("/",),
        created_by="p10-full-run",
        approval_source="local-juice-shop-read-only-full-run",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


def session(engagement_id: str, profile_root: Path) -> BrowserSessionRef:
    return BrowserSessionManager(profile_root).create_session(
        engagement_id=engagement_id,
        profile_ref="p10-full-run",
        authenticated_origins=(),
        cookie_fingerprint="sha256:" + "0" * 64,
    )


def redacted_observation(outcome) -> dict[str, object]:
    observation = dict(outcome.observation or {})
    allowed = {
        "handler_id", "handler_version", "target_backed", "observation_role",
        "target_fingerprint", "request_digest", "response_digest", "status_code",
        "final_url_shape_digest", "dialog_count", "network_event_count",
        "network_event_shape_digests", "dom_digest", "screenshot_digest", "replayable",
    }
    result = {key: observation[key] for key in allowed if key in observation}
    result.update(
        {"handler_status": str(outcome.status)[:40], "reason": str(outcome.reason)[:240]}
    )
    result.update(
        {
            "has_raw_response": False,
            "has_raw_headers": False,
            "has_cookies": False,
            "has_probe_value": False,
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", default=ORIGIN)
    args = parser.parse_args()
    normalized_origin = origin(args.origin)
    ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    approved = [
        item for item in ground_truth.get("cases", [])
        if item.get("expected") is True
        and item.get("mapping_status") == "approved"
        and item.get("oracle_status") == "frozen_contract_pending_live_proof"
    ]
    approved_ids = [str(item["case_id"]) for item in approved]
    mapping_review = ground_truth.get("independence", {}).get("mapping_review", {})
    validation = validate_mapping_review(
        mapping_review,
        expected_mapping_hash=EXPECTED_MAPPING,
        expected_oracle_contract_hash=EXPECTED_ORACLE,
        expected_case_ids=approved_ids,
        expected_class_count=6,
        expected_out_of_scope_case_ids=mapping_review.get("out_of_scope_confirmed", []),
    )
    if not validation["valid"]:
        raise SystemExit("mapping_review_invalid")

    run_id = str(args.run_id)
    workspace_id = f"juice-p10-{run_id}"
    namespace = f"artifact://juice-shop/p10/{run_id}"
    profile_root = Path("/tmp") / f"webpent-p10-full-{run_id}"
    shutil.rmtree(profile_root, ignore_errors=True)
    profile_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    observations: dict[str, dict[str, object]] = {}
    statuses: dict[str, str] = {}
    target_contacted = False

    for index, item in enumerate(approved, start=1):
        case_id = str(item["case_id"])
        case = get_juice_shop_safe_case(case_id)
        engagement_id = f"{workspace_id}-case-{index:02d}"
        current_scope = scope(engagement_id)
        current_session = session(engagement_id, profile_root)
        probe_store = EphemeralProbeStore()
        handler = PlaywrightBrowserHandler(
            target_origin=normalized_origin,
            engagement_id=engagement_id,
            profile_root=None,
            headless=True,
            browser_timeout_ms=15_000,
            probe_resolver=probe_store.resolve,
        )
        adapter = BrowserActionAdapter(
            handler,
            probe_registrar=probe_store.put,
            probe_cleaner=probe_store.clear,
        )
        target_url = urljoin(normalized_origin + "/", case.path.lstrip("/"))
        decision = evaluate_scope(current_scope, target_url, method="GET")
        probe = None
        if case.operation == "typed_search":
            statuses[case_id] = "blocked_by_precondition"
            observations[case_id] = {
                "target_backed": False,
                "reason": "typed_search_requires_causal_three_observation_proof",
                "has_raw_response": False,
                "has_raw_headers": False,
                "has_cookies": False,
                "has_probe_value": False,
            }
            continue
        request = BrowserActionRequest(
            action_id=f"{run_id}-action-{index:02d}",
            engagement_id=engagement_id,
            session_id=current_session.session_id,
            operation="navigate",
            url=target_url,
            scope_decision=decision,
            timeout_ms=15_000,
            idempotency_key=f"{run_id}:case:{index:02d}",
            observation_role="inventory",
        )
        try:
            outcome = adapter.execute(
                request,
                current_session,
                allow_operations=frozenset({"navigate"}),
            )
            observations[case_id] = redacted_observation(outcome)
            target_contacted = target_contacted or bool(observations[case_id].get("target_backed"))
            statuses[case_id] = (
                "observation_only"
                if observations[case_id].get("target_backed")
                else "blocked_by_precondition"
            )
        finally:
            _ = probe

    summary = {
        "schema_version": "p10.juice_shop.full_run.v1",
        "operation": "p10_full_run",
        "run_id": run_id,
        "workspace_id": workspace_id,
        "artifact_namespace": namespace,
        "workspace_recorded": True,
        "artifact_namespace_recorded": True,
        "target": normalized_origin,
        "target_contacted": target_contacted,
        "target_integrity": {
            "target_unchanged_measured": False,
            "reason": "no_package_integrity_adapter",
        },
        "mapped_case_ids": approved_ids,
        "executed_case_ids": approved_ids,
        "candidate_case_ids": [],
        "proof_case_ids": [],
        "replay_case_ids": [],
        "mapping_status": "mapping_approved_only",
        "observations": observations,
        "case_statuses": statuses,
        "central_store_put": False,
        "central_verify_seal": False,
        "proof_bundle_sealed": False,
        "central_replay": False,
        "replay_status": "not_reached",
        "qualification_claim": "none",
        "raw_data_retained": False,
        "raw_data_printed": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "run_id": run_id,
                "executed": len(approved_ids),
                "target_contacted": target_contacted,
                "proof_cases": 0,
                "qualification_claim": "none",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
