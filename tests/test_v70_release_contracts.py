from __future__ import annotations

import pytest

from webpent.agents.team import get_role_spec, validate_role_artifact
from webpent.benchmark.metrics import evaluate
from webpent.models.proof_bundle import build_proof_bundle, validate_proof_bundle
from webpent.shared.copilot_boundary import sanitize_copilot_suggestion
from webpent.shared.coverage_ledger import CoverageIntelligence
from webpent.validators.causal_validator import validate_causal_observation
from webpent.validators.proof_validator import validate_bundle_structure
from webpent.validators.replay_validator import validate_replay


def _coverage_state(entries, outcomes=()):
    return {"campaign_ledger": {"entries": entries}, "proof_outcomes": list(outcomes)}


def test_coverage_empty_state_has_zero_denominators() -> None:
    metrics = CoverageIntelligence().metrics({})
    assert metrics["campaign_count"] == 0
    assert metrics["tested_ratio"] == 0.0
    assert metrics["confirmation_ratio"] == 0.0


def test_coverage_counts_clean_as_tested() -> None:
    state = _coverage_state(
        [{"id": 1, "key": "xss", "status": "not_scanned"}],
        [{"campaign_key": "xss", "status": "clean"}],
    )
    metrics = CoverageIntelligence().metrics(state)
    assert metrics["tested_count"] == 1
    assert metrics["gap_count"] == 0


def test_coverage_counts_policy_block_as_blocked() -> None:
    state = _coverage_state(
        [{"id": 1, "key": "admin", "status": "not_scanned"}],
        [{"campaign_key": "admin", "status": "policy_block"}],
    )
    metrics = CoverageIntelligence().metrics(state)
    assert metrics["blocked_count"] == 1
    assert metrics["gap_count"] == 1


def test_coverage_keeps_human_review_as_gap() -> None:
    state = _coverage_state(
        [{"id": 1, "key": "jwt", "status": "not_scanned"}],
        [{"campaign_key": "jwt", "status": "human_review_only"}],
    )
    assert CoverageIntelligence().gaps(state)[0]["status"] == "human_review_only"


def test_copilot_rejects_non_mapping() -> None:
    assert sanitize_copilot_suggestion(["not", "a", "mapping"]) is None


def test_copilot_rejects_missing_action_class() -> None:
    assert sanitize_copilot_suggestion({"target_ref": "endpoint:/"}) is None


def test_copilot_rejects_invalid_information_gain() -> None:
    value = {"action_class": "research", "target_ref": "/", "expected_information_gain": "high"}
    assert sanitize_copilot_suggestion(value) is None


def test_copilot_clamps_information_gain() -> None:
    value = {"action_class": "research", "target_ref": "/", "expected_information_gain": 4}
    assert sanitize_copilot_suggestion(value)["expected_information_gain"] == 1.0


def test_benchmark_deduplicates_finding_keys() -> None:
    report = evaluate(["xss", "xss", " ", "sqli"], ["xss", "sqli"])
    assert report.predicted_count == 2
    assert report.true_positive_count == 2
    assert report.precision == 1.0


def test_benchmark_clamps_tested_surfaces_to_total() -> None:
    report = evaluate([], [], tested_surface_count=50, total_surface_count=3)
    assert report.coverage == 1.0


def test_benchmark_reproducibility_detects_different_run() -> None:
    report = evaluate(["xss"], ["xss"], independent_runs=[["xss"], ["sqli"]])
    assert report.reproducibility == 0.5


def test_benchmark_report_serializes_all_metrics() -> None:
    payload = evaluate(["xss"], ["xss"]).as_dict()
    assert {"precision", "recall", "coverage", "evidence_quality"}.issubset(payload)


def test_causal_validator_rejects_non_boolean_signal() -> None:
    value = {"causal_signal": 1, "negative_control_complete": True, "evidence_refs": ["r"]}
    assert not validate_causal_observation(value)


def test_causal_validator_rejects_empty_reference() -> None:
    value = {"causal_signal": True, "negative_control_complete": True, "evidence_refs": [" "]}
    assert not validate_causal_observation(value)


def test_replay_validator_rejects_malformed_bundle() -> None:
    assert not validate_replay({"sealed": True}, [], None)


def test_replay_validator_requires_negative_control_when_digest_exists() -> None:
    evidence = ({"status": 200},)
    negative = {"status": 403}
    bundle = build_proof_bundle(
        engagement_id="e",
        finding_id="f",
        evidence=evidence,
        evidence_refs=["r"],
        negative_control=negative,
    ).seal()
    assert not validate_replay(bundle, list(evidence), None)


def test_team_registry_rejects_unknown_role() -> None:
    assert get_role_spec("unknown-role") is None


def test_team_registry_rejects_missing_declared_artifact() -> None:
    assert not validate_role_artifact("validator", {})


def test_unsealed_proof_is_not_structurally_valid() -> None:
    bundle = build_proof_bundle(engagement_id="e", finding_id="f", evidence=[{"ok": True}])
    assert not validate_bundle_structure(bundle)
    assert not validate_proof_bundle(bundle)


def test_sealed_proof_bundle_is_immutable() -> None:
    bundle = build_proof_bundle(
        engagement_id="e", finding_id="f", evidence=[{"ok": True}], evidence_refs=["r"]
    ).seal()
    with pytest.raises(ValueError, match="immutable"):
        bundle.append_custody(actor="reviewer", action="review")
