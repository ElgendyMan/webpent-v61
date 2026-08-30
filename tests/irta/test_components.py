import pytest

from webpent.irta.business import DisposableWorkflowFixture, WorkflowRecord, WorkflowState
from webpent.irta.generator import generate_target
from webpent.irta.metrics import CaseOutcome, score_outcomes
from webpent.irta.negative import CleanDisposition, FalsePositiveSuppressionEngine
from webpent.irta.research import ResearchController, ResearchStage


def test_research_plan_is_bounded_and_evidence_aware():
    plan = ResearchController().build_plan(generate_target(9), "campaign-9")
    assert plan.stages == tuple(ResearchStage)
    assert len(plan.hypotheses) == 4
    assert "missing_causal_oracle" in plan.stop_conditions
    assert all(
        "independent_negative_control" in hypothesis.evidence_requirements
        for hypothesis in plan.hypotheses
    )


def test_negative_engine_does_not_turn_blocked_into_false_negative_or_clean():
    bundle = FalsePositiveSuppressionEngine().evaluate(
        "case-1",
        candidate_observed=False,
        control_observed=False,
        causal_oracle_passed=False,
        proof_replayable=False,
    )
    assert bundle.disposition is CleanDisposition.BLOCKED
    assert not bundle.evidence_digest


def test_workflow_fixture_enforces_roles_and_restores_snapshot():
    fixture = DisposableWorkflowFixture(WorkflowRecord("wf-1", "owner", "requester", 100))
    fixture.snapshot()
    fixture.transition("requester", "submit")
    with pytest.raises(PermissionError):
        fixture.transition("requester", "approve")
    fixture.transition("owner", "approve")
    fixture.apply_coupon("requester")
    assert fixture.record.state is WorkflowState.APPROVED
    assert fixture.record.coupon_uses == 1
    fixture.restore()
    assert fixture.record.state is WorkflowState.DRAFT
    assert fixture.record.coupon_uses == 0


def test_scoring_excludes_blocked_and_inconclusive_from_confusion_matrix():
    card = score_outcomes(
        (
            CaseOutcome("tp", True, "confirmed"),
            CaseOutcome("tn", False, "clean"),
            CaseOutcome("fp", False, "confirmed"),
            CaseOutcome("fn", True, "clean"),
            CaseOutcome("blocked", True, "blocked"),
            CaseOutcome("uncertain", True, "inconclusive"),
        )
    )
    assert (card.evaluated, card.tp, card.tn, card.fp, card.fn) == (4, 1, 1, 1, 1)
    assert (card.blocked, card.inconclusive) == (1, 1)
