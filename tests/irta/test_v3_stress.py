from webpent.irta.v3 import StressKind, assess_stress, default_stress_scenarios


def test_default_stress_suite_covers_required_hard_cases() -> None:
    scenarios = default_stress_scenarios()
    kinds = {scenario.kind for scenario in scenarios}
    assert kinds == {
        StressKind.SAME_STATUS,
        StressKind.MISLEADING_BODY,
        StressKind.PARTIAL_AUTHORIZATION,
        StressKind.TENANT_CONFUSION,
        StressKind.WORKFLOW_ORDERING,
    }


def test_stress_without_causal_proof_is_blocked() -> None:
    for scenario in default_stress_scenarios():
        assessment = assess_stress(scenario, has_causal_proof=False)
        assert assessment.outcome == "BLOCKED"


def test_same_status_candidate_control_does_not_score() -> None:
    scenario = next(
        item for item in default_stress_scenarios() if item.kind is StressKind.SAME_STATUS
    )
    assessment = assess_stress(scenario, has_causal_proof=True)
    assert assessment.outcome == "BLOCKED"
    assert "indistinguishable" in assessment.reason
