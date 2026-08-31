from webpent.irta.v3 import build_case_inventory, build_independent_targets, score_cases


def test_inventory_meets_shape_without_claiming_quality() -> None:
    cases = build_case_inventory(build_independent_targets())
    score = score_cases(cases)
    assert score.targets == 5
    assert score.cases == 50
    assert score.classes == 6
    assert score.blocked == 50
    assert score.tp == 0
    assert score.fp == 0
    assert score.fn == 0


def test_incomplete_bundle_is_blocked_not_scored() -> None:
    cases = build_case_inventory(build_independent_targets())
    score = score_cases(cases[:1])
    assert score.blocked == 1
    assert score.proof_complete == 0
