from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.check_scoring_readiness_packages import validate_package

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = sorted(
    (ROOT / "reports/evaluation/scoring_readiness").glob(
        "*-SCORING-READINESS-PACK-v1.json"
    )
)


def _packages() -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in PACKAGES]


def test_all_target_packages_validate_without_target_io() -> None:
    assert {package["target"]["target_id"] for package in _packages()} == {
        "owasp_juice_shop",
        "owasp_webgoat",
        "crapi",
    }
    for package in _packages():
        assert validate_package(package) == ()


def test_unadmitted_targets_have_no_scoring_contract_or_quality_metrics() -> None:
    for package in _packages():
        if package["target"]["target_id"] in {"owasp_webgoat", "crapi"}:
            assert package["ground_truth"]["approved_case_ids"] == []
            assert package["ground_truth"]["approved_class_count"] == 0
            assert package["quality_baseline"]["quality_metrics"] is None
            assert package["readiness_status"] == "blocked_no_admitted_scoring_cases"


def test_juice_shop_cases_require_causal_and_proof_fields() -> None:
    package = next(
        package
        for package in _packages()
        if package["target"]["target_id"] == "owasp_juice_shop"
    )
    assert len(package["case_contracts"]) == 3
    for case in package["case_contracts"]:
        assert case["causal_predicate"]
        assert case["safe_precondition"]
        assert case["independent_negative_control"]
        assert case["central_verifier_mapping"]
        assert case["seal"] is True
        assert case["verify_seal"] is True
        assert case["replay"] is True


def test_validator_rejects_observation_only_as_approved_case() -> None:
    package = next(
        package
        for package in _packages()
        if package["target"]["target_id"] == "owasp_juice_shop"
    )
    mutated = copy.deepcopy(package)
    mutated["case_contracts"][0]["candidate_status"] = "observation_only"
    assert "case_contracts[0]:candidate_status_invalid" in validate_package(mutated)


def test_validator_rejects_open_official_p10_gate() -> None:
    package = next(
        package
        for package in _packages()
        if package["target"]["target_id"] == "owasp_juice_shop"
    )
    mutated = copy.deepcopy(package)
    mutated["scope"]["official_isolated_p10_runs_authorized"] = True
    assert "scope:official_p10_gate_must_be_false" in validate_package(mutated)


def test_validator_rejects_non_semantic_predicate() -> None:
    package = next(
        package
        for package in _packages()
        if package["target"]["target_id"] == "owasp_juice_shop"
    )
    mutated = copy.deepcopy(package)
    mutated["case_contracts"][0]["causal_predicate"] = "HTTP 200 alone"
    assert "case_contracts[0]:causal_predicate_must_be_semantic" in validate_package(mutated)
