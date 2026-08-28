from __future__ import annotations

from webpent.dcvu import (
    DetectionQualityValidationEngine,
    build_default_fixtures,
    build_ground_truth_registry,
)
from webpent.dcvu.contracts import Verdict


def test_engine_discovers_all_generic_surfaces_without_truth_input() -> None:
    fixtures = build_default_fixtures()
    engine = DetectionQualityValidationEngine()
    assert len(engine.discover_case_ids(fixtures[0])) == 6
    assert all("vulnerable" not in item for item in engine.discover_case_ids(fixtures[0]))


def test_engine_produces_causal_positive_and_replayable_proof() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    evaluations = DetectionQualityValidationEngine().evaluate_target(fixtures[0], registry)
    assert len(evaluations) == 6
    assert all(item.verdict is Verdict.TRUE_POSITIVE for item in evaluations)
    assert all(item.proof_complete and item.replay_verified for item in evaluations)
    assert all(len(item.observations) == 3 for item in evaluations)
    assert all(not item.decision.execution_allowed for item in evaluations)
    assert all(not item.decision.qualification_effect for item in evaluations)


def test_engine_distinguishes_clean_cases_on_other_targets() -> None:
    fixtures = build_default_fixtures()
    registry = build_ground_truth_registry(fixtures)
    evaluations = DetectionQualityValidationEngine().evaluate_target(fixtures[1], registry)
    by_class = {item.ground_truth.case.vulnerability_class: item for item in evaluations}
    assert by_class["idor_bola"].verdict is Verdict.TRUE_POSITIVE
    assert by_class["privilege_escalation"].verdict is Verdict.TRUE_NEGATIVE
    assert by_class["business_logic_abuse"].verdict is Verdict.TRUE_NEGATIVE
    assert by_class["tenant_isolation"].verdict is Verdict.TRUE_POSITIVE
