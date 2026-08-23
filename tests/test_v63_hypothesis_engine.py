from __future__ import annotations

from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.research.experiment_manager import ExperimentManager
from webpent.research.hypothesis_engine import HypothesisEngine
from webpent.research.hypothesis_ranker import HypothesisRanker


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        target_url="https://lab.local/api/invoice/1",
        statement="A normal user may access another invoice.",
        confidence_score=0.8,
        novelty_score=0.4,
        evidence_refs=["obs:initial"],
    )


def test_hypothesis_lifecycle_requires_explicit_proof_signals() -> None:
    hypothesis = _hypothesis()
    investigating = HypothesisEngine.transition(
        hypothesis,
        HypothesisStatus.INVESTIGATING,
        reason="scope and target are known",
    )
    assert investigating.accepted
    assert investigating.new_status == "investigating"

    weak = HypothesisEngine.record_experiment(
        investigating.hypothesis,
        {"outcome": "validated", "causal_signal": True, "evidence_refs": ["obs:weak"]},
    )
    assert not weak.accepted
    assert weak.hypothesis.status == "investigating"

    valid = HypothesisEngine.record_experiment(
        investigating.hypothesis,
        {
            "outcome": "validated",
            "causal_signal": True,
            "negative_control_complete": True,
            "evidence_refs": ["obs:causal"],
        },
    )
    assert valid.accepted
    assert valid.hypothesis.status == "resolved_true"
    assert "obs:causal" in valid.hypothesis.evidence_refs


def test_hypothesis_lifecycle_learns_only_after_resolution() -> None:
    hypothesis = _hypothesis()
    early = HypothesisEngine.record_experiment(
        hypothesis,
        {"outcome": "learned", "evidence_refs": ["obs:early"]},
    )
    assert not early.accepted
    assert early.hypothesis.status == "unexplored"

    investigating = HypothesisEngine.transition(
        hypothesis,
        HypothesisStatus.INVESTIGATING,
        reason="experiment target selected",
    )
    rejected = HypothesisEngine.record_experiment(
        investigating.hypothesis,
        {
            "outcome": "rejected",
            "negative_control_complete": True,
            "evidence_refs": ["obs:negative"],
        },
    )
    learned = HypothesisEngine.record_experiment(
        rejected.hypothesis,
        {"outcome": "learned", "evidence_refs": ["lesson:invoice-access"]},
    )
    assert rejected.accepted
    assert rejected.hypothesis.status == "resolved_false"
    assert learned.accepted
    assert learned.hypothesis.status == "learned"


def test_hypothesis_ranker_is_stable_and_ignores_closed_items() -> None:
    first = _hypothesis()
    second = first.model_copy(update={"confidence_score": 0.9})
    closed = first.model_copy(update={"status": HypothesisStatus.ABANDONED})
    ranked = HypothesisRanker.rank([first, second, closed])

    assert [item.id for item in ranked] == [second.id, first.id]
    assert HypothesisRanker.rank([first, second]) == ranked


def test_experiment_manager_bounds_and_redacts_records() -> None:
    manager = ExperimentManager()
    record = manager.record(
        "hyp-1",
        {
            "outcome": "validated",
            "causal_signal": True,
            "negative_control_complete": True,
            "evidence_refs": ["obs:1"],
            "request": "Authorization: secret",
        },
    )
    assert record["evidence_refs"] == ["obs:1"]
    assert "request" not in record
    assert len(manager.records()) == 1


def test_experiment_manager_builds_bounded_template_and_evidence_lifecycle() -> None:
    manager = ExperimentManager()
    plan = manager.plan(
        hypothesis_id="hypidor",
        engagement_id="engagement:test",
        template="idor",
        inputs={"actor_refs": ["identity:a", "identity:b"], "object_ref": "object:1"},
    )
    assert plan["template_id"] == "idor"
    assert plan["approval_required"] is True
    assert plan["stages"] == ["input", "action", "observation", "validator", "evidence"]
    assert plan["max_steps"] <= 8
    assert "object:1" not in str(plan["inputs"])

    blocked = manager.plan(
        hypothesis_id="hyp-missing",
        engagement_id="engagement:test",
        template="idor",
        inputs={},
    )
    assert blocked["status"] == "blocked"
    assert blocked["reason"] == "required_experiment_inputs_missing"
    assert blocked["missing_inputs"] == ["actor_refs", "object_ref"]
    assert blocked["execution_mode"] == "proposal_only"

    record = manager.record(
        "hypidor",
        {
            "engagement_id": "engagement:test",
            "template_id": "idor",
            "outcome": "validated",
            "baseline": {"status": 403},
            "candidate": {"status": 200},
            "negative_control": {"status": 403},
            "causal_signal": True,
            "negative_control_complete": True,
            "negative_control_independent": True,
            "target_backed": True,
            "evidence_refs": ["obs:baseline", "obs:candidate", "obs:control"],
            "proof_bundle_id": "proof_bundle_1",
            "replayable": True,
            "validator_id": "idor_differential",
            "cleanup_status": "complete",
            "request": "Authorization: secret",
        },
    )
    assert record["engagement_id"] == "engagement:test"
    assert record["template_id"] == "idor"
    assert record["evidence_roles"] == ["baseline", "candidate", "negative_control"]
    assert record["proof_bundle_id"] == "proof_bundle_1"
    assert record["replayable"] is True
    assert record["validator_id"] == "idor_differential"
    assert record["cleanup_status"] == "complete"
    assert "baseline" not in record
    assert "candidate" not in record
    assert "negative_control" not in record
    assert "request" not in record
