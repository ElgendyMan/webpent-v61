from webpent.business_logic import (
    AbuseCaseGenerator,
    InvariantChecker,
    StateTransitionAnalyzer,
    WorkflowAnalyzer,
)
from webpent.models.workflows import WorkflowObservation

TARGET = "target-local"
ENGAGEMENT = "engagement-local"
BASE_URL = "http://127.0.0.1:8080"


def _observation(
    *,
    from_state: str = "order_created",
    to_state: str = "payment_pending",
    destructive: bool = False,
    **changes: object,
) -> WorkflowObservation:
    payload = {
        "fingerprint": "a" * 64,
        "workflow_key": "order",
        "transition_key": "order-transition",
        "source_ref": "test:workflow",
        "endpoint": f"{BASE_URL}/orders/42",
        "method": "POST",
        "from_state": from_state,
        "to_state": to_state,
        "signals": ["method_sequence", "workflow_intent"],
        "prerequisites": ["authenticated_identity"],
        "identity_ref": "identity:redacted",
        "identity_context": ["authenticated"],
        "evidence_refs": ["workflow:abc12345"],
        "scope_decision": "allowed",
        "destructive": destructive,
        **changes,
    }
    return WorkflowObservation(**payload)


def test_workflow_analyzer_delegates_to_passive_canonical_engine() -> None:
    analysis = WorkflowAnalyzer().analyze(
        {
            "requests": [
                {
                    "url": "/orders/42/approve",
                    "method": "POST",
                    "state": "payment_pending",
                    "next_state": "paid",
                    "requires_auth": True,
                    "parameters": {"order_id": "redacted"},
                }
            ]
        },
        target_url=BASE_URL,
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
        scope_checker=lambda endpoint: endpoint.startswith(BASE_URL),
    )

    assert analysis.target_id == TARGET
    assert analysis.engagement_id == ENGAGEMENT
    assert analysis.observations
    assert analysis.hypotheses
    assert analysis.promotion_status == "candidate_only"


def test_state_transition_analyzer_marks_only_unlisted_transition_as_candidate() -> None:
    observation = _observation(from_state="order_created", to_state="shipped")
    candidates = StateTransitionAnalyzer().find_candidates(
        [observation],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
        allowed_transitions={("order_created", "payment_pending")},
    )

    assert len(candidates) == 1
    assert candidates[0].source_state == "order_created"
    assert candidates[0].target_state == "shipped"
    assert candidates[0].promotion_status == "candidate_only"
    assert "central_sealed_replayable_proof_bundle" in candidates[0].required_validation


def test_invariant_checker_never_returns_confirmed_status() -> None:
    result = InvariantChecker().check(
        [
            _observation(
                from_state="paid",
                to_state="paid",
                destructive=True,
                authorization_boundary="cross_identity",
                identity_ref=None,
                identity_context=[],
            )
        ],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )

    assert result
    assert {item.status for item in result} == {"candidate_violation"}
    assert not any(item.status == "confirmed" for item in result)


def test_abuse_case_generator_wraps_existing_hypotheses_as_candidates() -> None:
    proposals = AbuseCaseGenerator().generate(
        [_observation()],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
        target_url=BASE_URL,
    )

    assert proposals
    assert all(item.target_id == TARGET for item in proposals)
    assert all(item.engagement_id == ENGAGEMENT for item in proposals)
    assert all(item.promotion_status == "candidate_only" for item in proposals)
    assert all("target_backed_causal_signal" in item.required_controls for item in proposals)
