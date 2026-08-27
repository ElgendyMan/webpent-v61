from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from webpent.vabhic_v7.analytics_review import AutonomousResearchAnalyticsV7, VIPReadinessReviewV7
from webpent.vabhic_v7.benchmark import SCENARIO_CLASSES, VIPControlledBenchmarkV6
from webpent.vabhic_v7.contracts import (
    BenchmarkDisposition,
    DiscoveryCandidateV2,
    Disposition,
    ResearchCommand,
    SecurityMentalModel,
)
from webpent.vabhic_v7.core import VABHICV7Core


def sample_inputs() -> tuple[object, object]:
    world = SimpleNamespace(
        assets=[{"name": "recorded-resource"}],
        business_logic=[{"description": "approval requires a reviewed state"}],
        user_journeys=[{"name": "submit then review"}],
        invariants=[{"statement": "only intended role may approve"}],
    )
    graph = SimpleNamespace(
        nodes=[
            {
                "id": "resource",
                "kind": "asset",
                "label": "recorded-resource",
                "criticality": "high",
            },
            {
                "id": "boundary",
                "kind": "permission",
                "label": "role boundary",
                "criticality": "critical",
            },
        ],
        relations=[{"id": "rel", "relation": "permission boundary", "label": "role to resource"}],
    )
    return world, graph


def test_full_v7_lifecycle_is_advisory_and_zero_request():
    world, graph = sample_inputs()
    result = VABHICV7Core().run(
        engagement_id="e-v7",
        target_id="target-recorded",
        world_model=world,
        attack_graph=graph,
        evidence_refs=("artifact:recorded",),
    )
    assert result.command_plan.commands
    assert result.mental_model.protected_assets
    assert result.candidates
    assert len(result.narratives) == len(result.candidates)
    assert result.allocations
    assert len(result.coordination.contributions) == 5
    assert all(item.disposition == Disposition.BLOCKED for item in result.skepticism)
    assert result.requests_sent == 0
    assert not result.mutations_performed
    assert not result.finding_created
    assert not result.qualification_approved


def test_command_contract_requires_stop_and_success_criteria():
    with pytest.raises(ValueError, match="success_and_stop"):
        ResearchCommand(
            command_id="x",
            objective="x",
            reasoning="x",
            expected_value=0.5,
            confidence=0.5,
            cost=0.2,
            risk=0,
            success_criteria=(),
            stop_criteria=(),
        )


def test_mental_model_marks_missing_boundaries_advisory():
    world, _ = sample_inputs()
    result = VABHICV7Core().run(
        engagement_id="e", target_id="t", world_model=world, attack_graph=None
    )
    assert result.mental_model.status.value == "advisory"
    assert result.mental_model.unresolved_questions


def test_discovery_candidate_cannot_be_confirmed():
    with pytest.raises(ValueError, match="cannot_confirm"):
        DiscoveryCandidateV2(
            candidate_id="x",
            security_assumption="assumption",
            observed_evidence=(),
            reasoning_chain=("reason",),
            possible_impact="impact",
            validation_path=("validate",),
            causal_confirmation=True,
        )


def test_budget_penalizes_repeated_path():
    candidate = DiscoveryCandidateV2(
        candidate_id="candidate",
        security_assumption="a",
        observed_evidence=(),
        reasoning_chain=("r",),
        possible_impact="i",
        validation_path=("v",),
    )
    allocation = VABHICV7Core().budget.allocate(
        candidates=(candidate,), attempted_ids=("candidate",)
    )[0]
    assert allocation.duplicate_penalty == 1.0
    assert allocation.utility < 0.5
    assert not allocation.selected


def test_benchmark_registers_six_blocked_cases_without_requests():
    report = VIPControlledBenchmarkV6().evaluate()
    assert tuple(report["registered_classes"]) == SCENARIO_CLASSES
    assert report["scenario_class_count"] == 6
    assert report["blocked_case_count"] == 6
    assert report["scorable_case_count"] == 0
    assert report["requests_sent"] == 0
    assert report["real_world_detection_rate"] is None
    assert all(case["disposition"] == BenchmarkDisposition.BLOCKED for case in report["cases"])


def test_analytics_keeps_metrics_null_without_valid_ground_truth():
    benchmark = VIPControlledBenchmarkV6().evaluate()
    analytics = AutonomousResearchAnalyticsV7().report(
        engagement_id="e", target_id="t", benchmark=benchmark, commands=5, candidates=5
    )
    assert not analytics.valid_ground_truth
    assert analytics.research_efficiency is None
    assert analytics.real_world_detection_rate is None
    review = VIPReadinessReviewV7().review(
        engagement_id="e", target_id="t", benchmark=benchmark, analytics=analytics
    )
    assert review.status.value == "blocked"
    assert not review.vip_granted
    assert not review.p10_opened


def test_authority_contracts_are_fail_closed():
    with pytest.raises(ValueError):
        ResearchCommand(
            command_id="x",
            objective="x",
            reasoning="x",
            expected_value=0.5,
            confidence=0.5,
            cost=0.2,
            risk=0.0,
            success_criteria=("s",),
            stop_criteria=("p",),
            execution_requested=True,
        )
    with pytest.raises(ValueError):
        SecurityMentalModel(
            model_id="x",
            protected_assets=(),
            business_logic=(),
            user_journeys=(),
            trust_relationships=(),
            authorization_boundaries=(),
            state_machines=(),
            sensitive_workflows=(),
            security_assumptions=(),
        )
    assert FrozenInstanceError is not None
