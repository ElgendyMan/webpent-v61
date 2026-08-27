from webpent.models.hypothesis import HypothesisStatus
from webpent.research_engine.feedback_loop import (
    ObservationFeedback,
    ObservationFeedbackLoop,
)
from webpent.research_engine.hypothesis_manager import HypothesisDraft, HypothesisManager
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory

HYPOTHESIS_ID = "11111111-1111-4111-8111-111111111111"


def _hypothesis():
    return HypothesisManager().create(
        HypothesisDraft(
            target_id="controlled://target-a",
            vulnerability_class="idor",
            reasoning="attacker may read an unrelated owner resource",
            validation_method="owner baseline plus independent negative control",
            confidence=0.8,
        ),
        engagement_id="eng-arex",
        hypothesis_id=HYPOTHESIS_ID,
    )


def test_validated_feedback_requires_central_proof_and_stays_open_without_it():
    loop = ObservationFeedbackLoop(
        memory=SecurityReasoningMemory(engagement_id="eng-arex", target_id="target-a")
    )
    result = loop.apply(
        _hypothesis(),
        ObservationFeedback(
            hypothesis_id=HYPOTHESIS_ID,
            outcome="validated",
            causal_signal=True,
            negative_control_complete=True,
            central_proof=False,
            evidence_refs=("observation://candidate",),
        ),
    )

    assert result.outcome == "inconclusive"
    assert result.new_status == HypothesisStatus.INVESTIGATING.value
    assert result.advisory_only is True
    assert result.learning_memory_id is not None


def test_proof_backed_validated_feedback_resolves_true_and_learns():
    memory = SecurityReasoningMemory(engagement_id="eng-arex", target_id="target-a")
    result = ObservationFeedbackLoop(memory=memory).apply(
        _hypothesis(),
        ObservationFeedback(
            hypothesis_id=HYPOTHESIS_ID,
            outcome="validated",
            causal_signal=True,
            negative_control_complete=True,
            central_proof=True,
            evidence_refs=("proof://sealed-bundle",),
            rationale="central verifier accepted the causal experiment",
        ),
    )

    assert result.accepted is True
    assert result.new_status == HypothesisStatus.RESOLVED_TRUE.value
    assert result.learning_memory_id is not None
    lessons = memory.retrieve_learning(HYPOTHESIS_ID)
    assert len(lessons.items) == 1
    assert lessons.items[0].metadata["advisory_only"] is True


def test_rejected_feedback_without_negative_control_is_inconclusive():
    result = ObservationFeedbackLoop().apply(
        _hypothesis(),
        ObservationFeedback(
            hypothesis_id=HYPOTHESIS_ID,
            outcome="rejected",
            causal_signal=False,
            negative_control_complete=False,
            evidence_refs=("observation://candidate",),
        ),
    )

    assert result.outcome == "inconclusive"
    assert result.new_status == HypothesisStatus.INVESTIGATING.value
    assert "negative control" in result.stop_reason


def test_missing_task_capability_is_blocked_and_not_validated():
    result = ObservationFeedbackLoop().apply_task_feedback(
        task={"required_capability": ""},  # type: ignore[arg-type]
        hypothesis=_hypothesis(),
        feedback=ObservationFeedback(
            hypothesis_id=HYPOTHESIS_ID,
            outcome="validated",
            causal_signal=True,
            negative_control_complete=True,
            central_proof=True,
            evidence_refs=("proof://sealed-bundle",),
        ),
    )

    assert result.outcome == "blocked"
    assert result.new_status == HypothesisStatus.INVESTIGATING.value
    assert result.accepted is False


def test_apply_to_campaign_updates_bounded_state_from_explicit_feedback():
    import hashlib

    from webpent.research_engine.campaign_state import CampaignState

    hypothesis = _hypothesis()
    state = CampaignState(
        campaign_id="campaign-feedback-001",
        target_identity="controlled-loopback-id-oracle",
        scope_digest=hashlib.sha256(b"loopback-only").hexdigest(),
        active_hypotheses=(HYPOTHESIS_ID,),
    )
    feedback = ObservationFeedback(
        hypothesis_id=HYPOTHESIS_ID,
        outcome="blocked",
        rationale="precondition gate remained closed",
        evidence_refs=("gate:precondition-blocked",),
    )

    result, updated = ObservationFeedbackLoop().apply_to_campaign(
        state,
        "task-feedback-001",
        hypothesis,
        feedback,
        discovered_assets=("asset:controlled-resource", "asset:controlled-resource"),
        evidence_summary={"observation_count": "0"},
    )

    assert result.outcome == "blocked"
    assert "task-feedback-001" in updated.blocked_tasks
    assert HYPOTHESIS_ID in updated.active_hypotheses
    assert updated.discovered_assets == ("asset:controlled-resource",)
    assert updated.evidence_summary["observation_count"] == "0"
    assert updated.evidence_summary[f"feedback:{HYPOTHESIS_ID}"] == "blocked"
    assert "gate:precondition-blocked" in updated.evidence_summary[f"evidence:{HYPOTHESIS_ID}"]


def test_apply_to_campaign_removes_resolved_hypothesis_and_keeps_only_refs():
    import hashlib

    from webpent.research_engine.campaign_state import CampaignState

    hypothesis = _hypothesis()
    state = CampaignState(
        campaign_id="campaign-feedback-002",
        target_identity="controlled-loopback-id-oracle",
        scope_digest=hashlib.sha256(b"loopback-only").hexdigest(),
        active_hypotheses=(HYPOTHESIS_ID,),
    )
    feedback = ObservationFeedback(
        hypothesis_id=HYPOTHESIS_ID,
        outcome="validated",
        causal_signal=True,
        negative_control_complete=True,
        central_proof=True,
        evidence_refs=("proof:sealed-redacted-001",),
    )

    result, updated = ObservationFeedbackLoop().apply_to_campaign(
        state,
        "task-feedback-002",
        hypothesis,
        feedback,
    )

    assert result.accepted is True
    assert result.new_status == "resolved_true"
    assert HYPOTHESIS_ID not in updated.active_hypotheses
    assert "task-feedback-002" in updated.completed_tasks
    assert "proof:sealed-redacted-001" in updated.evidence_summary[f"evidence:{HYPOTHESIS_ID}"]
