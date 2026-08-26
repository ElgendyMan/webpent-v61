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
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from webpent.benchmark.juice_shop_target_adapter import (
    JUICE_SHOP_TARGET_REGISTRATION,
)
from webpent.benchmark.p10_review import validate_mapping_review
from webpent.config.settings import ScanMode, Settings
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.browser_proof_runner import BrowserProofRunner, EphemeralProbe
from webpent.shared.campaign_executor import ActionExecutor
from webpent.shared.control_plane import (
    BrowserActionRequest,
    BrowserSessionRef,
    compile_scope,
    evaluate_scope,
)
from webpent.shared.control_plane_runtime import (
    BrowserActionAdapter,
    BrowserSessionManager,
)
from webpent.shared.control_plane_spine import build_control_plane_runtime
from webpent.shared.g02_contract import G02_HTTP_APPROVAL_EXPIRY
from webpent.shared.playwright_adapter import EphemeralProbeStore, PlaywrightBrowserHandler
from webpent.shared.runtime import (
    CONTROL_PLANE_BROWSER_CANONICAL_WRAPPER,
    CONTROL_PLANE_BROWSER_INVENTORY_REF,
    CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
    CONTROL_PLANE_BROWSER_SCOPE_POLICY,
    AdapterRegistry,
    RegisteredAdapter,
)
from webpent.shared.semantic_proof_runner import SemanticProofRunner
from webpent.shared.target_adapters import TargetAdapterRegistry

ORIGIN = "http://127.0.0.1:3000"
EXPECTED_MAPPING = "sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5"
EXPECTED_ORACLE = "sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c"
EXECUTION_ORACLE_STATUSES = frozenset(
    {"frozen_contract_pending_live_proof", "approved_oracle_pending_full_set_metrics"}
)
NEUTRAL_PROBE = "p10-neutral-observation"
TARGET_CONTAINER = "juice-shop-local"
def target_integrity_snapshot() -> dict[str, object]:
    """Read only immutable Docker metadata for the local target container."""
    command = [
        "sudo",
        "docker",
        "inspect",
        "--format",
        "{{.Id}}|{{.Image}}|{{.Config.Image}}|{{.Config.Hostname}}",
        TARGET_CONTAINER,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "reason": "docker_inspect_unavailable"}
    if result.returncode != 0:
        return {"available": False, "reason": "docker_inspect_failed"}
    fields = result.stdout.strip().split("|", 3)
    if len(fields) != 4 or not all(fields):
        return {"available": False, "reason": "docker_inspect_metadata_incomplete"}
    return {
        "available": True,
        "container_id_digest": digest(fields[0]),
        "image_id_digest": digest(fields[1]),
        "config_image_digest": digest(fields[2]),
        "hostname_digest": digest(fields[3]),
    }


def target_integrity_result(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    """Compare redacted immutable target metadata without retaining Docker output."""
    comparable = (
        before.get("available") is True
        and after.get("available") is True
        and before.keys() == after.keys()
    )
    unchanged = comparable and all(
        before[key] == after[key] for key in before if key != "available"
    )
    return {
        "target_unchanged_measured": unchanged,
        "measurement_method": "docker_inspect_immutable_metadata",
        "before_available": before.get("available") is True,
        "after_available": after.get("available") is True,
        "reason": (
            "immutable_metadata_match"
            if unchanged
            else "immutable_metadata_mismatch_or_unavailable"
        ),
    }


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
        "semantic_profile", "semantic_observation_version", "content_type_family",
        "response_length_bucket", "semantic_path_digest", "metric_line_count_bucket",
        "policy_directive_count_bucket", "log_record_count_bucket",
        "signature_field_count_bucket", "semantic_reason", "semantic_match",
        "semantic_oracle_ready", "directory_shape", "verbose_error_shape",
        "scoreboard_shape",
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


def build_browser_executor(
    origin_value: str, handler: PlaywrightBrowserHandler
) -> ActionExecutor:
    """Build the approved browser executor; no direct transport is introduced."""
    registry = AdapterRegistry()
    registry.register(
        RegisteredAdapter(
            name="control_plane_browser",
            capability="browser_action",
            transport="playwright",
            handler=handler,
            source="p10-full-run",
            version="1",
            policy_checked=True,
            canonical_wrapper=CONTROL_PLANE_BROWSER_CANONICAL_WRAPPER,
            scope_policy=CONTROL_PLANE_BROWSER_SCOPE_POLICY,
            static_inventory_ref=CONTROL_PLANE_BROWSER_INVENTORY_REF,
            proof_contract=CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
            expires_at=G02_HTTP_APPROVAL_EXPIRY,
        )
    )
    settings = Settings(
        scan_mode=ScanMode.SAFE_SMART,
        smart_require_idempotency=True,
        smart_action_budget=20.0,
        smart_max_actions=12,
    )
    authority = ActionAuthority(
        settings=settings,
        allowed_origin=origin_value,
        manifest={"capabilities": {"browser_action": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    return ActionExecutor(authority)


def xss_finding(case_id: str, target_url: str) -> Finding:
    """Create endpoint-only finding context; ephemeral probe values never enter it."""
    return Finding(
        title=f"Juice Shop {case_id} browser proof",
        severity=Severity.HIGH,
        description="Local typed-search sink validation context.",
        tool_name="juice-shop-p10-browser-adapter",
        url=target_url,
        vuln_class=VulnClass.XSS,
        payload=None,
        evidence=None,
    )


def semantic_finding(case_id: str, target_url: str) -> Finding:
    """Create an info-disclosure context; no response content enters the finding."""
    return Finding(
        title=f"Juice Shop {case_id} semantic proof context",
        severity=Severity.MEDIUM,
        description="Local redacted semantic response validation context.",
        tool_name="juice-shop-p10-semantic-adapter",
        url=target_url,
        vuln_class=VulnClass.INFO_DISCLOSURE,
        payload=None,
        evidence=None,
    )


def xss_causal_predicate(baseline, candidate, negative_control):
    """Require a target-backed sink effect plus independent neutral control."""
    signal = (
        int(candidate.get("dialog_count", 0) or 0)
        > int(baseline.get("dialog_count", 0) or 0)
        and int(candidate.get("dialog_count", 0) or 0)
        > int(negative_control.get("dialog_count", 0) or 0)
        and baseline.get("response_digest") != candidate.get("response_digest")
        and candidate.get("response_digest")
        != negative_control.get("response_digest")
        and candidate.get("status_code") == baseline.get("status_code")
        and negative_control.get("status_code") == baseline.get("status_code")
    )
    return signal, "target_backed_dialog_response_differential"


def blocked_metadata_proof(reason: str) -> tuple[None, dict[str, object]]:
    """Explicitly refuse to promote route/resource metadata to a vulnerability."""
    return None, {"status": "blocked_by_precondition", "reason": reason}


def record_proof_result(
    case_id: str,
    proof_result,
    *,
    observations: dict[str, dict[str, object]],
    statuses: dict[str, str],
    proof_states: dict[str, dict[str, object]],
    proof_bundles: dict[str, dict[str, object]],
) -> None:
    """Record an attestation only when every central promotion guard passes."""
    observations[case_id] = {
        role: dict(value) for role, value in proof_result.observations.items()
    }
    if proof_result.passed and proof_result.attestation:
        attestation = dict(proof_result.attestation)
        nested_bundle = attestation.get("proof_bundle")
        nested_bundle = nested_bundle if isinstance(nested_bundle, dict) else {}
        promotion_guard = attestation.get("promotion_guard")
        promotion_guard = (
            promotion_guard if isinstance(promotion_guard, dict) else {}
        )
        sealed = (
            attestation.get("proof_bundle_sealed") is True
            and nested_bundle.get("sealed") is True
        )
        replay_status = (
            "passed"
            if promotion_guard.get("replay_verified") is True
            and promotion_guard.get("replayable") is True
            and promotion_guard.get("status") == "passed"
            else "not_verified"
        )
        proof_verified = attestation.get("proof_verified") is True
        causal_signal = attestation.get("causal_signal") is True
        negative_control_complete = (
            attestation.get("negative_control_complete") is True
        )
        promotion_ready = (
            proof_verified
            and sealed
            and replay_status == "passed"
            and causal_signal
            and negative_control_complete
        )
        proof_bundles[case_id] = attestation
        statuses[case_id] = (
            "confirmed_proof" if promotion_ready else "confirmed_metadata_only"
        )
        proof_states[case_id] = {
            "status": statuses[case_id],
            "verify_seal": sealed,
            "replay_status": replay_status,
            "promotion_ready": promotion_ready,
            "causal_signal": causal_signal,
            "negative_control_complete": negative_control_complete,
        }
        return
    statuses[case_id] = "blocked_by_precondition"
    proof_states[case_id] = {
        "status": "blocked_by_precondition",
        "reason": proof_result.reason,
        "diagnostics": dict(proof_result.diagnostics),
    }


def execute_navigation(
    adapter: BrowserActionAdapter,
    current_session: BrowserSessionRef,
    current_scope,
    *,
    run_id: str,
    index: int,
    engagement_id: str,
    origin_value: str,
    path: str,
    ordinal: int,
) -> dict[str, object]:
    """Execute one bounded GET and return only redacted browser metadata."""
    target_url = urljoin(origin_value + "/", path.lstrip("/"))
    decision = evaluate_scope(current_scope, target_url, method="GET")
    request = BrowserActionRequest(
        action_id=f"{run_id}-action-{index:02d}-{ordinal}",
        engagement_id=engagement_id,
        session_id=current_session.session_id,
        operation="navigate",
        url=target_url,
        scope_decision=decision,
        timeout_ms=15_000,
        idempotency_key=f"{run_id}:case:{index:02d}:observation:{ordinal}",
        observation_role="proof_candidate" if ordinal == 2 else "proof_control",
    )
    outcome = adapter.execute(
        request,
        current_session,
        allow_operations=frozenset({"navigate"}),
    )
    return redacted_observation(outcome)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", default=ORIGIN)
    args = parser.parse_args()
    normalized_origin = origin(args.origin)
    target_registry = TargetAdapterRegistry()
    target_registry.register(JUICE_SHOP_TARGET_REGISTRATION)
    target_registration = target_registry.require_for_origin(normalized_origin)
    target_adapter = target_registration.adapter
    ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    execution_cases = [
        item for item in ground_truth.get("cases", [])
        if item.get("expected") is True
        and item.get("mapping_status") == "approved"
        and item.get("oracle_status") in EXECUTION_ORACLE_STATUSES
    ]
    execution_ids = [str(item["case_id"]) for item in execution_cases]
    approved_mapping_cases = [
        item for item in ground_truth.get("cases", [])
        if item.get("expected") is True
        and item.get("mapping_status") == "approved"
    ]
    approved_mapping_ids = [str(item["case_id"]) for item in approved_mapping_cases]
    mapping_review = ground_truth.get("independence", {}).get("mapping_review", {})
    validation = validate_mapping_review(
        mapping_review,
        expected_mapping_hash=EXPECTED_MAPPING,
        expected_oracle_contract_hash=EXPECTED_ORACLE,
        expected_case_ids=approved_mapping_ids,
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
    target_integrity_before = target_integrity_snapshot()

    proof_bundles: dict[str, dict[str, object]] = {}
    proof_states: dict[str, dict[str, object]] = {}
    for index, item in enumerate(execution_cases, start=1):
        case_id = str(item["case_id"])
        case = target_adapter.case(case_id)
        if case is None:
            statuses[case_id] = "target_case_not_registered"
            proof_states[case_id] = {
                "status": "target_case_not_registered",
                "reason": "target_adapter_case_missing",
            }
            continue
        engagement_id = f"{workspace_id}-case-{index:02d}"
        current_scope = scope(engagement_id)
        case_profile_root = profile_root / f"case-{index:02d}"
        case_profile_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        probe_store = EphemeralProbeStore()
        handler = PlaywrightBrowserHandler(
            target_origin=normalized_origin,
            engagement_id=engagement_id,
            profile_root=case_profile_root / "browser-profile",
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
            executor=build_browser_executor(normalized_origin, handler),
            profile_root=str(case_profile_root / "runtime-profile"),
        )
        current_session = control_plane.session_manager.create_session(
            engagement_id=engagement_id,
            profile_ref="p10-full-run",
            authenticated_origins=(),
            cookie_fingerprint="sha256:" + "0" * 64,
        )

        if case.operation == "typed_search":
            target_url = urljoin(normalized_origin + "/", case.path.lstrip("/"))
            probes = {
                "baseline": EphemeralProbe.from_value(
                    "baseline", "p10-neutral-baseline", probe_ref=f"probe://{run_id}/{case_id}/baseline"
                ),
                "candidate": EphemeralProbe.from_value(
                    "candidate",
                    "<iframe src=\"javascript:alert(`xss`)\">",
                    probe_ref=f"probe://{run_id}/{case_id}/candidate",
                ),
                "negative_control": EphemeralProbe.from_value(
                    "negative_control", "p10-neutral-negative", probe_ref=f"probe://{run_id}/{case_id}/negative"
                ),
            }
            proof_runner = BrowserProofRunner(
                replay_engine=control_plane.replay_engine,
                adapter=adapter,
                session=current_session,
                scope=current_scope,
                engagement_id=engagement_id,
                validator_id="juice-shop-p10-xss-browser-adapter",
                validator_version="1",
                browser_operation="typed_search",
                workflow_id=case.workflow_id,
                workflow_allowlist=target_adapter.workflow_ids(),
            )
            proof_result = proof_runner.run(
                xss_finding(case_id, target_url),
                baseline=probes["baseline"],
                candidate=probes["candidate"],
                negative_control=probes["negative_control"],
                causal_predicate=xss_causal_predicate,
                scope_context={
                    "target_origin": normalized_origin,
                    "target_path": case.path,
                    "scope_bound": True,
                },
                identity_context={
                    "mode": "anonymous",
                    "session_ref": current_session.session_id,
                    "credentials_retained": False,
                },
                target_url=target_url,
                replay_metadata={"case_id": case_id, "oracle_id": case.oracle_id},
                probe_values={
                    probes[role].probe_ref: value
                    for role, value in {
                        "baseline": "p10-neutral-baseline",
                        "candidate": "<iframe src=\"javascript:alert(`xss`)\">",
                        "negative_control": "p10-neutral-negative",
                    }.items()
                },
            )
            observations[case_id] = {
                role: dict(value) for role, value in proof_result.observations.items()
            }
            target_contacted = target_contacted or any(
                value.get("target_backed") is True
                for value in proof_result.observations.values()
            )
            record_proof_result(
                case_id,
                proof_result,
                observations=observations,
                statuses=statuses,
                proof_states=proof_states,
                proof_bundles=proof_bundles,
            )
            continue

        semantic_profile = case.semantic_profile
        if case.operation == "navigate" and semantic_profile:
            try:
                target_url = urljoin(normalized_origin + "/", case.path.lstrip("/"))
                semantic_runner = SemanticProofRunner(
                    replay_engine=control_plane.replay_engine,
                    adapter=adapter,
                    session=current_session,
                    scope=current_scope,
                    engagement_id=engagement_id,
                    semantic_profile=semantic_profile,
                    semantic_profiles=target_adapter.semantic_profiles,
                    validator_id="juice-shop-p10-semantic-adapter",
                    validator_version="1",
                )
                proof_result = semantic_runner.run(
                    semantic_finding(case_id, target_url),
                    baseline_url=urljoin(normalized_origin + "/", ""),
                    candidate_url=target_url,
                    negative_control_url=urljoin(
                        normalized_origin + "/",
                        "p10-negative-control-not-found",
                    ),
                    scope_context={
                        "target_origin": normalized_origin,
                        "target_path": case.path,
                        "scope_bound": True,
                    },
                    identity_context={
                        "mode": "anonymous",
                        "session_ref": current_session.session_id,
                        "credentials_retained": False,
                    },
                    replay_metadata={
                        "case_id": case_id,
                        "oracle_id": case.oracle_id,
                    },
                )
                target_contacted = target_contacted or any(
                    value.get("target_backed") is True
                    for value in proof_result.observations.values()
                )
                record_proof_result(
                    case_id,
                    proof_result,
                    observations=observations,
                    statuses=statuses,
                    proof_states=proof_states,
                    proof_bundles=proof_bundles,
                )
            except Exception as exc:
                statuses[case_id] = "adapter_error"
                proof_states[case_id] = {
                    "status": "adapter_error",
                    "reason": type(exc).__name__,
                }
                observations[case_id] = {
                    "target_backed": False,
                    "reason": "semantic_adapter_execution_failed",
                    "error_type": type(exc).__name__,
                    "has_raw_response": False,
                    "has_raw_headers": False,
                    "has_cookies": False,
                    "has_probe_value": False,
                }
            continue

        try:
            baseline = execute_navigation(
                adapter,
                current_session,
                current_scope,
                run_id=run_id,
                index=index,
                engagement_id=engagement_id,
                origin_value=normalized_origin,
                path=case.path,
                ordinal=1,
            )
            candidate = execute_navigation(
                adapter,
                current_session,
                current_scope,
                run_id=run_id,
                index=index,
                engagement_id=engagement_id,
                origin_value=normalized_origin,
                path=case.path,
                ordinal=2,
            )
            negative_control = execute_navigation(
                adapter,
                current_session,
                current_scope,
                run_id=run_id,
                index=index,
                engagement_id=engagement_id,
                origin_value=normalized_origin,
                path="/p10-negative-control-not-found",
                ordinal=3,
            )
            observations[case_id] = {
                "candidate": candidate,
                "negative_control": negative_control,
                "baseline": baseline,
            }
            target_contacted = target_contacted or bool(
                baseline.get("target_backed") or candidate.get("target_backed")
            )
            _, proof_state = blocked_metadata_proof(
                "route_or_resource_metadata_is_not_vulnerability_proof"
            )
            proof_states[case_id] = proof_state
            statuses[case_id] = (
                "observation_only"
                if candidate.get("target_backed")
                else "blocked_by_precondition"
            )
        except Exception as exc:
            statuses[case_id] = "adapter_error"
            proof_states[case_id] = {"status": "adapter_error", "reason": type(exc).__name__}
            observations[case_id] = {
                "target_backed": False,
                "reason": "adapter_execution_failed",
                "error_type": type(exc).__name__,
                "has_raw_response": False,
                "has_raw_headers": False,
                "has_cookies": False,
                "has_probe_value": False,
            }

    target_integrity_after = target_integrity_snapshot()
    target_integrity = target_integrity_result(
        target_integrity_before,
        target_integrity_after,
    )

    valid_proof_case_ids = sorted(
        case_id
        for case_id, state in proof_states.items()
        if state.get("promotion_ready") is True
    )
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
        "target_integrity": target_integrity,
        "mapped_case_ids": approved_mapping_ids,
        "executed_case_ids": execution_ids,
        "candidate_case_ids": valid_proof_case_ids,
        "proof_case_ids": valid_proof_case_ids,
        "replay_case_ids": valid_proof_case_ids,
        "mapping_status": "mapping_approved_only",
        "observations": observations,
        "case_statuses": statuses,
        "proof_states": proof_states,
        "proof_bundles": proof_bundles,
        "central_store_put": bool(valid_proof_case_ids),
        "central_verify_seal": bool(valid_proof_case_ids) and all(
            proof_states[case_id].get("verify_seal") is True
            for case_id in valid_proof_case_ids
        ),
        "proof_bundle_sealed": bool(valid_proof_case_ids) and all(
            proof_states[case_id].get("verify_seal") is True
            for case_id in valid_proof_case_ids
        ),
        "central_replay": bool(valid_proof_case_ids) and all(
            proof_states[case_id].get("replay_status") == "passed"
            for case_id in valid_proof_case_ids
        ),
        "replay_status": (
            "passed"
            if valid_proof_case_ids
            and all(
                proof_states[case_id].get("replay_status") == "passed"
                for case_id in valid_proof_case_ids
            )
            else "not_reached"
        ),
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
                "executed": len(execution_ids),
                "target_contacted": target_contacted,
                "proof_cases": len(valid_proof_case_ids),
                "qualification_claim": "none",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
