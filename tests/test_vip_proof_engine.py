from webpent.models.proof_bundle import build_proof_bundle
from webpent.models.proof_engine import ProofActionStatus, ProofGapType
from webpent.shared.proof_engine import (
    apply_proof_outcome,
    build_proof_engine_update,
    build_proof_plan,
    classify_probe_gaps,
    plan_next_proof_actions,
)


def _sealed_bundle(action_id: str):
    return build_proof_bundle(
        engagement_id="engagement-fixture",
        finding_id=f"finding:{action_id}",
        hypothesis_id=f"hypothesis:{action_id}",
        target_fingerprint="target:fixture",
        scope_context={"origin": "https://fixture.local"},
        identity_context={"identity_ref": "user:fixture"},
        evidence=({"payload": "fixture"},),
        evidence_refs=["evref:proof-1"],
        baseline={"status": 200, "body": "baseline"},
        negative_control={"status": 200, "body": "negative"},
        request_evidence=({"method": "GET", "path": "/fixture"},),
        response_evidence=({"status": 200, "body": "candidate"},),
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id="validator:fixture",
        validator_version="1.0",
        replay_metadata={"replayable": True},
        cleanup_status="complete",
    ).seal(actor="test")


def test_classify_probe_gaps_preserves_explicit_gap_taxonomy() -> None:
    gaps = classify_probe_gaps(
        campaign_key="download_idor",
        evidence={"surface": "download", "oracle": {"status": 200}},
        source_refs=["surface:download-1"],
        required=[
            "surface",
            "identity",
            "body",
            "content_type",
            "precondition",
            "negative_control",
            "oracle",
            "validator_id",
        ],
    )

    assert {gap.gap_type for gap in gaps} == {
        ProofGapType.MISSING_IDENTITY,
        ProofGapType.MISSING_BODY_CONTENT_TYPE,
        ProofGapType.MISSING_PRECONDITION,
        ProofGapType.MISSING_NEGATIVE_CONTROL,
        ProofGapType.MISSING_VALIDATOR,
        ProofGapType.WEAK_ORACLE,
    }
    assert all(gap.source_refs == ["surface:download-1"] for gap in gaps)
    assert all(gap.evidence_fingerprint.startswith("sha256:") for gap in gaps)


def test_policy_block_is_terminal_and_cannot_authorize_execution() -> None:
    gaps = classify_probe_gaps(
        campaign_key="swagger_ssrf",
        evidence={"scope_block": True},
        required=[],
    )
    plan = build_proof_plan(gaps)

    assert len(plan.actions) == 1
    assert plan.actions[0].status == ProofActionStatus.TERMINAL
    assert plan.actions[0].approval_required is True
    assert plan.actions[0].budget_requests == 1
    assert plan.actions[0].action_type == "request_policy_review"


def test_proof_engine_does_not_repeat_without_new_evidence() -> None:
    gaps = classify_probe_gaps(
        campaign_key="tenant_context_switching",
        evidence={},
        required=["identity", "negative_control"],
    )
    first_actions, first_dropped = plan_next_proof_actions(gaps)
    second_actions, second_dropped = plan_next_proof_actions(
        gaps,
        existing_actions=[action.model_dump(mode="json") for action in first_actions],
    )

    assert len(first_actions) == 2
    assert first_dropped == 0
    assert second_actions == []
    assert second_dropped == 2


def test_proof_plan_contains_causal_edges_and_bounded_actions() -> None:
    gaps = classify_probe_gaps(
        campaign_key="xslt_injection",
        evidence={"surface": "transform"},
        required=["negative_control", "oracle"],
    )
    plan = build_proof_plan(gaps, max_actions=1)

    assert len(plan.assessments) == 2
    assert len(plan.actions) == 1
    assert len(plan.causal_edges) == 1
    assert plan.causal_edges[0]["relation"] == "gap_requires_action"
    assert plan.actions[0].approval_required is True
    assert plan.actions[0].budget_requests <= 20
    assert plan.plan_digest.startswith("sha256:")


def test_proof_outcome_updates_chain_without_confirming_a_finding() -> None:
    gaps = classify_probe_gaps(
        campaign_key="tenant_context_switching",
        evidence={},
        required=["identity"],
    )
    plan = build_proof_plan(gaps)
    action = plan.actions[0]
    updated = apply_proof_outcome(
        action,
        {
            "action_id": action.action_id,
            "status": "confirmed",
            "evidence_refs": ["evidence:tenant-proof"],
            "evidence_complete": True,
            "causal_signal": True,
            "negative_control_observed": True,
            "cleanup_status": "complete",
            "proof_bundle": _sealed_bundle(action.action_id),
        },
    )

    assert updated.status == "executed"
    assert updated.confidence_after == "evidence_ready_for_review"
    assert updated.cleanup_status == "complete"
    assert updated.chain_state["state"] == "confirmed"
    assert updated.confidence_after != "confirmed"


def test_confirmation_flags_without_bundle_are_fail_closed() -> None:
    action = build_proof_plan(
        classify_probe_gaps(
            campaign_key="header_sqli",
            evidence={},
            required=["validator_id"],
        )
    ).actions[0]
    updated = apply_proof_outcome(
        action,
        {
            "action_id": action.action_id,
            "status": "confirmed",
            "evidence_complete": True,
            "causal_signal": True,
            "negative_control_observed": True,
        },
    )

    assert updated.confidence_after == "needs_human_review"
    assert updated.chain_state["promotion_ready"] is False
    assert updated.chain_state["state"] == "needs_human_review"


def test_scope_block_outcome_is_terminal_and_not_confirmed() -> None:
    gaps = classify_probe_gaps(
        campaign_key="swagger_ssrf",
        evidence={"scope_block": True},
        required=[],
    )
    action = build_proof_plan(gaps).actions[0]
    updated = apply_proof_outcome(
        action,
        {"action_id": action.action_id, "status": "blocked_by_scope"},
    )

    assert updated.status == "terminal"
    assert updated.confidence_after == "needs_human_review"


def test_campaign_plan_is_projected_into_proof_observability() -> None:
    update = build_proof_engine_update(
        {
            "campaign_plan": {
                "entries": [
                    {
                        "key": "download_idor",
                        "gaps": [
                            "missing-validator:download_idor",
                            "missing-surface:download_idor",
                        ],
                        "matched_observation_refs": [],
                    }
                ]
            }
        }
    )

    assert update["proof_gap_assessments"]
    assert update["proof_plan"]["actions"]
    assert update["proof_observability"]["gap_counts"]["missing_validator"] == 1
    assert update["proof_observability"]["gap_counts"]["missing_surface"] == 1



def test_proof_outcome_projects_to_ledger_without_creating_finding() -> None:
    assessments = classify_probe_gaps(
        campaign_key="header_sqli",
        evidence={"surface": True},
        required=["validator_id"],
    )
    proof_plan = build_proof_plan(assessments)
    action = proof_plan.actions[0]
    state = {
        "proof_plan": proof_plan.model_dump(mode="json"),
        "proof_outcomes": [
            {
                "action_id": action.action_id,
                "campaign_key": "header_sqli",
                "vuln_class": "sqli",
                "target": "https://fixture.local/item?id=1&token=secret-value",
                "status": "confirmed",
                "evidence_complete": True,
                "causal_signal": True,
                "negative_control_observed": True,
                "cleanup_status": "complete",
                "evidence_refs": ["evref:proof-1"],
                "request_metadata": {"authorization": "Bearer secret-token"},
                "note": "bounded fixture outcome",
                "proof_bundle": _sealed_bundle(action.action_id).model_dump(mode="json"),
            }
        ],
        "evidence_ledger": [],
    }

    update = build_proof_engine_update(state)
    ledger = update["evidence_ledger"]

    assert len(ledger) == 1
    assert ledger[0]["entry_id"] == f"proof:{action.action_id}"
    assert ledger[0]["status"] == "tool_confirmed"
    assert ledger[0]["cleanup_status"] == "complete"
    assert "secret-value" not in str(ledger)
    assert "secret-token" not in str(ledger)
    assert "findings" not in update

    repeated = build_proof_engine_update({**state, "evidence_ledger": ledger})
    assert repeated["evidence_ledger"] == ledger
