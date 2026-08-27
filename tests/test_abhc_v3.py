from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.abhc import (
    ABHCCore,
    AdvisoryDisposition,
    AutonomousResearchDirector,
    AutonomousResearchReview,
    BoundedExperimentPlanner,
    FindingQualityEngine,
    HypothesisEvolutionEngine,
    HypothesisStatus,
    OracleEvidence,
    PotentialAttackChainReasoner,
    SecurityBoundaryReasoner,
    WeakSignal,
)
from webpent.abhc.exploration import AdaptiveSurfaceExplorer


def graph_fixture() -> dict[str, object]:
    return {
        "nodes": [
            {
                "id": "user",
                "kind": "identity",
                "label": "user identity",
                "criticality": "high",
                "confidence": 0.4,
            },
            {
                "id": "owner",
                "kind": "ownership",
                "label": "resource owner",
                "criticality": "high",
                "confidence": 0.5,
            },
            {
                "id": "workflow",
                "kind": "workflow",
                "label": "approval workflow",
                "criticality": "critical",
                "confidence": 0.7,
            },
            {
                "id": "record",
                "kind": "resource",
                "label": "protected record",
                "criticality": "medium",
                "confidence": 0.8,
            },
        ],
        "edges": [
            {
                "id": "e1",
                "source_id": "user",
                "target_id": "record",
                "kind": "permission",
                "evidence_refs": ("obs-auth",),
                "confidence": 0.6,
            },
            {
                "id": "e2",
                "source_id": "owner",
                "target_id": "record",
                "kind": "ownership",
                "evidence_refs": ("obs-owner",),
                "confidence": 0.5,
            },
            {
                "id": "e3",
                "source_id": "workflow",
                "target_id": "record",
                "kind": "state",
                "evidence_refs": ("obs-workflow",),
                "confidence": 0.7,
            },
        ],
    }


def test_director_is_deterministic_budgeted_and_advisory() -> None:
    director = AutonomousResearchDirector(budget=2.0)
    first = director.decide(attack_graph=graph_fixture(), coverage={"unexplored": ("record",)})
    second = director.decide(attack_graph=graph_fixture(), coverage={"unexplored": ("record",)})
    assert first == second
    assert len(first) == 2
    assert all(item.advisory_only for item in first)
    assert sum(item.budget_cost for item in first) <= 2.0


def test_explorer_prioritizes_sensitive_surfaces_and_tracks_gaps() -> None:
    report = AdaptiveSurfaceExplorer().explore(
        attack_graph=graph_fixture(), prior_coverage={"explored": ("record",)}
    )
    assert report.surfaces[0].category in {"identity", "workflow", "ownership"}
    assert "record" in report.coverage.explored
    assert report.coverage.unexplored
    assert report.knowledge_gaps
    assert report.advisory_only


def test_hypothesis_lifecycle_is_explicit_and_confirmation_is_fail_closed() -> None:
    report = AdaptiveSurfaceExplorer().explore(attack_graph=graph_fixture())
    hypothesis = HypothesisEvolutionEngine().create_from_surfaces(report, limit=1)[0]
    assert hypothesis.status is HypothesisStatus.NEW
    evolving = HypothesisEvolutionEngine().evolve(
        hypothesis, evidence_refs=("obs-1",), confidence=0.72, begin_validation=True
    )
    assert evolving.status is HypothesisStatus.VALIDATING
    with pytest.raises(ValueError, match="incomplete_oracle"):
        evolving.apply_oracle(
            OracleEvidence(causal_signal=True, actual_observation_refs=("obs-1",))
        )
    complete = evolving.apply_oracle(
        OracleEvidence(
            causal_signal=True,
            independent_negative_control=True,
            proof_bundle_complete=True,
            replay_verified=True,
            actual_observation_refs=("obs-1", "control-1"),
        )
    )
    assert complete.status is HypothesisStatus.CONFIRMED


def test_boundary_reasoning_and_experiment_planner_block_unsafe_capabilities() -> None:
    report = AdaptiveSurfaceExplorer().explore(attack_graph=graph_fixture())
    hypothesis = HypothesisEvolutionEngine().create_from_surfaces(report, limit=2)
    boundaries = SecurityBoundaryReasoner().map_boundaries(
        attack_graph=graph_fixture(), hypotheses=hypothesis
    )
    assert boundaries.boundaries
    plans = BoundedExperimentPlanner().plan(
        hypothesis,
        boundaries,
        available_capabilities=("login", "token_generation"),
        budget=2.0,
    )
    assert all(not plan.selected for plan in plans)
    assert all(plan.blocked_reason for plan in plans)


def test_quality_and_chain_reasoning_never_promote() -> None:
    report = AdaptiveSurfaceExplorer().explore(attack_graph=graph_fixture())
    hypothesis = HypothesisEvolutionEngine().create_from_surfaces(report, limit=1)[0]
    quality = FindingQualityEngine().assess(hypothesis)
    assert quality.disposition is AdvisoryDisposition.BLOCKED
    assert quality.promotion_allowed is False
    hypothesis = HypothesisEvolutionEngine().evolve(
        hypothesis, evidence_refs=("obs-auth",), confidence=0.8
    )
    boundaries = SecurityBoundaryReasoner().map_boundaries(
        attack_graph=graph_fixture(), hypotheses=(hypothesis,)
    )
    chains = PotentialAttackChainReasoner().reason(
        hypotheses=(hypothesis,),
        boundaries=boundaries.boundaries,
        weak_signals=(WeakSignal("signal-1", "boundary inconsistency", ("obs-auth",), 0.7),),
    )
    assert chains
    assert all(chain.status == "HYPOTHESIS" and chain.advisory_only for chain in chains)


def test_core_is_offline_and_review_is_not_qualification() -> None:
    output = ABHCCore(budget=3.0).research(
        attack_graph=graph_fixture(),
        prior_coverage={"unexplored": ("record",)},
        weak_signals=(WeakSignal("record", "weak ownership signal", (), 0.4),),
    )
    assert output.missions
    assert output.hypotheses
    assert output.requests_sent == 0
    assert output.mutation_performed is False
    assert output.review.qualification_allowed is False
    assert output.review.confirmed_finding_created is False
    assert output.review.disposition in {
        AdvisoryDisposition.BLOCKED,
        AdvisoryDisposition.INSUFFICIENT_EVIDENCE,
        AdvisoryDisposition.ADVISORY_CANDIDATE,
    }


def test_review_rejects_empty_research() -> None:
    report = AutonomousResearchReview().review(
        missions=(), hypotheses=(), boundaries=(), experiments=(), chains=(), quality_reports=()
    )
    assert report.disposition is AdvisoryDisposition.BLOCKED
    assert report.qualification_allowed is False
    assert report.confirmed_finding_created is False


def test_benchmark_artifact_is_conservative_and_six_class(tmp_path: Path) -> None:
    from benchmarks.abhc_v3_controlled import build_report

    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_id": "real-idor",
                        "class": "idor",
                        "causal_signal": True,
                        "negative_control": True,
                        "proof_bundle": True,
                        "replay_status": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = build_report(source)
    assert len(result["classes"]) == 6
    assert result["metrics"]["scorable_class_count"] == 1
    assert result["metrics"]["precision"] is None
    assert result["execution"]["requests_sent"] == 0
    assert result["governance"]["vip_status"] == "NOT_QUALIFIED"
