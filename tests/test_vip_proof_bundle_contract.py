from __future__ import annotations

import pytest

from webpent.models.proof_bundle import (
    build_proof_bundle,
    validate_proof_bundle,
)


def test_proof_bundle_seals_replays_and_requires_negative_control() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=[{"status": 200, "body": "safe-result"}],
        evidence_refs=["replay://finding-1/positive"],
        negative_control={"status": 403, "body": "blocked"},
    ).seal(actor="validator")

    assert bundle.verify_seal() is True
    assert validate_proof_bundle(bundle, require_negative_control=True) is True
    assert bundle.replay(
        [{"status": 200, "body": "safe-result"}],
        {"status": 403, "body": "blocked"},
    ) is True
    assert bundle.replay(
        [{"status": 200, "body": "safe-result"}],
        {"status": 200, "body": "blocked"},
    ) is False


def test_proof_bundle_is_immutable_after_sealing() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=["positive"],
        evidence_refs=["replay://finding-1/positive"],
    ).seal()

    with pytest.raises(ValueError, match="sealed_proof_bundle_is_immutable"):
        bundle.append_custody(actor="tester", action="mutate")


def test_proof_bundle_redacts_sensitive_values_before_digesting() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=[{"authorization": "Bearer secret-token", "value": "positive"}],
        evidence_refs=["replay://finding-1/positive"],
    ).seal()

    assert bundle.verify_seal() is True
    assert bundle.replay(
        [{"authorization": "Bearer different-token", "value": "positive"}],
    ) is True
    assert "secret-token" not in bundle.model_dump_json()


def test_unsealed_or_incomplete_bundle_is_not_valid() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=["positive"],
        evidence_refs=["replay://finding-1/positive"],
    )

    assert bundle.verify_seal() is False
    assert validate_proof_bundle(bundle) is False
    assert validate_proof_bundle(bundle, require_negative_control=True) is False
