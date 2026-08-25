from webpent.benchmark.p10_coverage import CoverageCase, validate_coverage


def _case(case_id: str, category: str, **overrides: object) -> CoverageCase:
    values = {
        "case_id": case_id,
        "category": category,
        "challenge_key": f"{case_id}-challenge",
        "workflow_id": f"{case_id}-workflow",
        "oracle_id": f"{case_id}-oracle",
        "mapping_status": "approved",
        "oracle_status": "ready",
        "safe_to_execute": True,
    }
    values.update(overrides)
    return CoverageCase(**values)


def test_draft_case_is_not_executable():
    case = _case(
        "case-1",
        "XSS",
        mapping_status="pending_independent_review",
        oracle_status="pending_safe_oracle",
        safe_to_execute=False,
    )
    result = validate_coverage([case], minimum_cases=1, minimum_classes=1)
    assert not case.executable
    assert result["coverage_passed"] is False
    assert "approved_case_mapping_below_minimum" in result["blocking_reasons"]
    assert "ready_oracle_count_below_minimum" in result["blocking_reasons"]


def test_approved_ready_safe_cases_pass_minimums():
    cases = [_case("case-1", "XSS"), _case("case-2", "Injection")]
    result = validate_coverage(cases, minimum_cases=2, minimum_classes=2)
    assert result["coverage_passed"] is True
    assert result["executable_case_count"] == 2
    assert result["executable_class_count"] == 2


def test_duplicate_case_ids_fail_closed():
    result = validate_coverage(
        [_case("same", "XSS"), _case("same", "Injection")],
        minimum_cases=1,
        minimum_classes=1,
    )
    assert result["coverage_passed"] is False
    assert "case_ids_not_unique_or_missing" in result["blocking_reasons"]
