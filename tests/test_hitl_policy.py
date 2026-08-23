import pytest

from webpent.shared.action_authority import ActionRequest, ActionRisk
from webpent.shared.hitl_policy import (
    HITLLevel,
    evaluate_hitl_action,
    evaluate_hitl_confirmation,
    resolve_hitl_policy,
)


def _request(risk: ActionRisk = ActionRisk.READ_ONLY) -> ActionRequest:
    return ActionRequest(
        task_id="task-1",
        engagement_id="engagement-1",
        target_url="https://fixture.example",
        risk=risk,
    )


def test_hitl_levels_have_explicit_progression_and_final_authority():
    assert resolve_hitl_policy(1).requires_human_approval is True
    assert ActionRisk.READ_ONLY in resolve_hitl_policy(2).autonomous_risks
    assert resolve_hitl_policy(3).requires_explicit_authorization is True
    assert resolve_hitl_policy(4).max_actions > resolve_hitl_policy(3).max_actions
    assert resolve_hitl_policy(4).as_dict()["authority_final_decision_required"] is True


def test_level_one_is_suggestion_only_even_with_human_approval_flag():
    decision = evaluate_hitl_action(
        _request(),
        HITLLevel.SUGGEST,
        scope_ready=True,
        human_approved=True,
    )
    assert decision.allowed_to_dispatch is False
    assert decision.advisory_only is True


def test_level_two_allows_only_scoped_read_only_actions():
    read_only = evaluate_hitl_action(_request(), 2, scope_ready=True)
    active = evaluate_hitl_action(
        _request(ActionRisk.ACTIVE), 2, scope_ready=True, human_approved=True
    )
    assert read_only.allowed_to_dispatch is True
    assert active.allowed_to_dispatch is False
    assert "hitl:risk_requires_human_review" in active.reasons


def test_levels_three_and_four_require_explicit_authorization_and_scope():
    denied = evaluate_hitl_action(_request(ActionRisk.ACTIVE), 4)
    allowed = evaluate_hitl_action(
        _request(ActionRisk.ACTIVE),
        4,
        explicit_authorization=True,
        scope_ready=True,
        budget_available=True,
    )
    assert denied.allowed_to_dispatch is False
    assert "hitl:scope_not_ready" in denied.reasons
    assert "hitl:explicit_authorization_required" in denied.reasons
    assert allowed.allowed_to_dispatch is True


def test_confirmation_requires_all_proof_and_replay_gates():
    incomplete = evaluate_hitl_confirmation(
        4,
        impact=True,
        root_cause=True,
        reproducible=True,
        evidence=True,
        proof_bundle_sealed=False,
        replay_passed=False,
    )
    complete = evaluate_hitl_confirmation(
        4,
        impact=True,
        root_cause=True,
        reproducible=True,
        evidence=True,
        proof_bundle_sealed=True,
        replay_passed=True,
    )
    assert incomplete.allowed_to_dispatch is False
    assert "confirmation:proof_bundle_sealed:missing" in incomplete.reasons
    assert "confirmation:replay_passed:missing" in incomplete.reasons
    assert complete.allowed_to_dispatch is True
    assert complete.requires_proof_for_confirmation is True


def test_unknown_level_fails_closed():
    with pytest.raises(ValueError):
        resolve_hitl_policy(5)
