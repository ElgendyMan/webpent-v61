from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from webpent.models.evidence import redact_sensitive
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.campaign_executor import CampaignExecutor
from webpent.shared.vip_vertical_slice import (
    CaseContract,
    LifecycleStage,
    TargetSpec,
    VIPAutonomousVerticalSlice,
)


def _target(**overrides: object) -> TargetSpec:
    values: dict[str, object] = {
        "target_id": "local-fixture",
        "canonical_origin": "http://127.0.0.1:3000",
        "scope": ("/fixture",),
        "method_policy": ("GET",),
        "request_budget": 8,
        "redirect_policy": "same_origin_only",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "authorization_ref": "local-fixture-owner-approval",
    }
    values.update(overrides)
    return TargetSpec(**values)


def _contract(case_id: str, *, confirmed: bool, target_local: bool = True) -> CaseContract:
    return CaseContract(
        case_id=case_id,
        vulnerability_class="fixture_causal_contract",
        capability="http_read",
        path="/fixture",
        causal_predicate="candidate_matches_controlled_fixture",
        safe_preconditions=("fixture_ready",),
        negative_control_contract="independent_control_passed",
        target_local=target_local,
        enabled=True,
    )


def _build_slice(*, ready: bool = True, confirmed: bool = True) -> VIPAutonomousVerticalSlice:
    authority = ActionAuthority(
        allowed_origin="http://127.0.0.1:3000",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority)

    state = {"confirmed": confirmed}

    def handler(task):
        phase = task.workflow_state
        if phase == "baseline":
            match = False
            reason = "baseline_observation"
        elif phase == "negative_control":
            match = False
            reason = "independent_control_passed"
        else:
            match = state["confirmed"]
            reason = task.metadata["causal_predicate"]
        return {
            "observation": {
                "handler_status": "completed",
                "observation_role": phase,
                "semantic_reason": reason,
                "semantic_match": match,
                "semantic_oracle_ready": True,
                "target_backed": True,
                "replayable": True,
            }
        }

    def change_handler(payload):
        assert payload["change_class"] == "target_local"
        state["confirmed"] = True
        return {"regression_passed": True, "changed": True}

    return VIPAutonomousVerticalSlice(
        authority=authority,
        executor=executor,
        capability_provider=lambda _target: {"http_read": {"available": True}},
        readiness_provider=lambda _target: {
            "ready": ready,
            "external_contact": False,
            "mutation": False,
        },
        observation_handler=handler,
        safe_change_handler=change_handler,
    )


def test_vertical_slice_confirms_with_causal_negative_seal_and_replay() -> None:
    result = _build_slice(confirmed=True).run(
        target=_target(),
        engagement_id="engagement-vip-local-001",
        contracts=[_contract("fixture-confirmed", confirmed=True)],
    )

    assert result["status"] == "completed"
    assert result["cases"][0]["status"] == "confirmed"
    assert result["cases"][0]["oracle"]["causal_signal"] is True
    proof = result["cases"][0]["proof"]
    assert proof["sealed"] is True
    assert proof["verify_seal"] is True
    assert proof["replay_status"] == "passed"
    assert proof["promotion_ready"] is True
    assert result["safety"]["official_isolated_p10_runs_authorized"] is False
    assert result["safety"]["qualification_claim"] is None
    lifecycle = [item["stage"] for item in result["lifecycle"]]
    for stage in (
        LifecycleStage.CREATE_CAMPAIGN,
        LifecycleStage.SELECT_SAFE_CASES,
        LifecycleStage.RUN_BASELINE,
        LifecycleStage.RUN_INDEPENDENT_NEGATIVE_CONTROL,
        LifecycleStage.EVALUATE_CENTRAL_ORACLE,
        LifecycleStage.VERIFY_SEAL,
        LifecycleStage.REPLAY,
        LifecycleStage.GENERATE_REPORT,
    ):
        if stage is LifecycleStage.GENERATE_REPORT:
            continue
        assert stage.value in lifecycle
    serialized = str(result)
    assert "must-not-be-persisted" not in serialized
    assert "password" not in serialized.lower()
    clean, redactions = redact_sensitive({"password": "must-not-be-persisted"})
    assert clean["password"] == "[REDACTED]"
    assert redactions


def test_vertical_slice_inconclusive_creates_owner_packet_and_keeps_gate_closed() -> None:
    result = _build_slice(confirmed=False).run(
        target=_target(),
        engagement_id="engagement-vip-local-002",
        contracts=[_contract("fixture-inconclusive", confirmed=False)],
    )

    case = result["cases"][0]
    assert case["proof"]["promotion_ready"] is True
    assert case["improvement"]["before_status"] == "observation_only"
    assert case["improvement"]["before_oracle"]["causal_signal"] is False
    assert case["improvement"]["retest"]["proof"]["promotion_ready"] is True
    assert case["owner_decision_packet"] is None
    proposal = case["improvement_proposal"]
    assert proposal["status"] == "proposed"
    assert proposal["failure_record"]["recorded_as"] == "failure_or_inconclusive_evidence"
    assert proposal["change_class"] == "target_local"
    assert result["safety"]["official_isolated_p10_runs_authorized"] is False
    assert result["safety"]["qualification_claim"] is None
    assert case["status"] == "confirmed"
    assert case["improvement"]["regression_passed"] is True
    assert case["improvement"]["retest"]["status"] == "completed"
    assert case["improvement"]["scoring_promotion"] is False


def test_vertical_slice_keeps_non_local_improvement_pending_owner_approval() -> None:
    result = _build_slice(confirmed=False).run(
        target=_target(),
        engagement_id="engagement-vip-local-002-gated",
        contracts=[_contract("fixture-gated-improvement", confirmed=False, target_local=False)],
    )

    case = result["cases"][0]
    packet = case["owner_decision_packet"]
    assert case["status"] == "observation_only"
    assert packet["status"] == "pending_owner_approval"
    assert "owner approval" in packet["decision_requested"]
    assert {
        "decision_requested",
        "why_it_is_needed",
        "evidence",
        "options",
        "risk",
        "files_or_commits_affected",
        "rollback",
        "recommended_decision",
        "status",
    } <= packet.keys()
    assert case["failure_record"]["recorded_as"] == "failure_or_inconclusive_evidence"
    assert case["improvement_proposal"]["change_class"] == "generic_candidate_requires_owner_review"
    assert case["improvement"] is None
    assert any(
        item["stage"] == LifecycleStage.IMPLEMENT_SAFE_LOCAL_CHANGE.value
        and item["status"] == "blocked"
        for item in result["lifecycle"]
    )
    assert result["safety"]["official_isolated_p10_runs_authorized"] is False


def test_vertical_slice_blocks_non_loopback_before_capability_or_handler() -> None:
    called = False
    slice_ = _build_slice()
    slice_.observation_handler = lambda _task: (_ for _ in ()).throw(
        AssertionError("must not execute")
    )
    result = slice_.run(
        target=_target(canonical_origin="https://external.example"),
        engagement_id="engagement-vip-local-003",
        contracts=[_contract("fixture-blocked", confirmed=True)],
    )

    assert result["status"] == "blocked"
    assert result["cases"] == []
    reasons = result["lifecycle"][1]["reasons"]
    assert "scope:loopback_origin_required" in reasons
    assert "authority:origin_mismatch" in reasons
    assert called is False


def test_vertical_slice_blocks_unready_target_without_promotion() -> None:
    result = _build_slice(ready=False).run(
        target=_target(),
        engagement_id="engagement-vip-local-004",
        contracts=[_contract("fixture-unready", confirmed=True)],
    )

    assert result["status"] == "blocked"
    assert result["cases"] == []
    readiness_event = next(
        item
        for item in result["lifecycle"]
        if item["stage"] == LifecycleStage.CHECK_TARGET_READINESS.value
    )
    assert readiness_event["status"] == "blocked"
    assert result["safety"]["official_isolated_p10_runs_authorized"] is False


def test_vertical_slice_rejects_credentials_wildcard_and_invalid_methods() -> None:
    slice_ = _build_slice()
    result = slice_.run(
        target=_target(
            canonical_origin="http://user:pass@127.0.0.1:3000/*",
            method_policy=("POST",),
        ),
        engagement_id="engagement-vip-local-005",
        contracts=[_contract("fixture-invalid-target", confirmed=True)],
    )

    assert result["status"] == "blocked"
    assert result["cases"] == []
    reasons = result["lifecycle"][1]["reasons"]
    assert "scope:embedded_credentials_forbidden" in reasons
    assert "scope:wildcard_origin_forbidden" in reasons
    assert "policy:read_only_methods_required" in reasons


def test_vertical_slice_blocks_external_contact_or_mutation_readiness() -> None:
    for readiness in (
        {"ready": True, "external_contact": True, "mutation": False},
        {"ready": True, "external_contact": False, "mutation": True},
    ):
        called = False
        slice_ = _build_slice()

        def forbidden_handler(_task: object) -> dict[str, object]:
            nonlocal called
            called = True
            return {}

        slice_.observation_handler = forbidden_handler
        slice_.readiness_provider = lambda _target, value=readiness: value
        result = slice_.run(
            target=_target(),
            engagement_id="engagement-vip-local-readiness-blocked",
            contracts=[_contract("fixture-readiness-blocked", confirmed=True)],
        )
        assert result["status"] == "blocked"
        assert result["cases"] == []
        assert called is False
        readiness_event = next(
            item
            for item in result["lifecycle"]
            if item["stage"] == LifecycleStage.CHECK_TARGET_READINESS.value
        )
        assert readiness_event["status"] == "blocked"


def test_vertical_slice_rejects_unavailable_capability_without_execution() -> None:
    slice_ = _build_slice()
    called = False

    def forbidden_handler(_task: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    slice_.observation_handler = forbidden_handler
    slice_.capability_provider = lambda _target: {"http_read": {"available": False}}
    result = slice_.run(
        target=_target(),
        engagement_id="engagement-vip-local-006",
        contracts=[_contract("fixture-unavailable-capability", confirmed=True)],
    )

    assert result["status"] == "completed"
    assert result["cases"] == []
    assert called is False
    selected = next(
        item
        for item in result["lifecycle"]
        if item["stage"] == LifecycleStage.SELECT_SAFE_CASES.value
    )
    assert selected["selected"] == []
    assert "capability:unavailable" in selected["rejected"][0]["reasons"]


def test_vertical_slice_rejects_case_without_causal_or_safe_contract() -> None:
    invalid = CaseContract(
        case_id="invalid-contract",
        vulnerability_class="fixture",
        capability="http_read",
        path="/fixture",
        causal_predicate="",
        safe_preconditions=(),
    )
    result = _build_slice().run(
        target=_target(),
        engagement_id="engagement-vip-local-007",
        contracts=[invalid],
    )

    assert result["status"] == "completed"
    assert result["cases"] == []
    selected = next(
        item
        for item in result["lifecycle"]
        if item["stage"] == LifecycleStage.SELECT_SAFE_CASES.value
    )
    assert "oracle:causal_predicate_required" in selected["rejected"][0]["reasons"]
    assert "precondition:safe_precondition_required" in selected["rejected"][0]["reasons"]


def test_vertical_slice_full_lifecycle_order_and_governance_invariants() -> None:
    result = _build_slice(confirmed=False).run(
        target=_target(),
        engagement_id="engagement-vip-local-008",
        contracts=[_contract("fixture-full-lifecycle", confirmed=False)],
    )
    stages = [item["stage"] for item in result["lifecycle"]]
    expected = [stage.value for stage in VIPAutonomousVerticalSlice.lifecycle]

    positions = [stages.index(stage) for stage in expected]
    assert positions == sorted(positions)
    assert result["cases"][0]["improvement"]["scoring_promotion"] is False
    assert result["safety"] == {
        "loopback_only": True,
        "external_contact": False,
        "credentials_used": False,
        "state_mutation": False,
        "raw_bodies_persisted": False,
        "raw_headers_persisted": False,
        "qualification_claim": None,
        "official_isolated_p10_runs_authorized": False,
    }


def test_vertical_slice_report_contains_no_sensitive_keys_or_raw_material() -> None:
    result = _build_slice().run(
        target=_target(),
        engagement_id="engagement-vip-local-009",
        contracts=[_contract("fixture-redaction-contract", confirmed=True)],
    )
    serialized = json.dumps(result, sort_keys=True).lower()
    for forbidden in ("password", "cookie", "token", "raw body content", "raw header content"):
        assert forbidden not in serialized
