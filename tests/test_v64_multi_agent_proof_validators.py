from __future__ import annotations

from webpent.agents.team import get_role_spec, team_manifest, validate_role_artifact
from webpent.models.proof_bundle import build_proof_bundle
from webpent.validators import (
    validate_bundle_structure,
    validate_causal_observation,
    validate_replay,
)


def test_proof_validators_require_seal_and_replayable_negative_control() -> None:
    evidence = ({"status": 200, "object_id": "1"},)
    negative = {"status": 403, "object_id": "1"}
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=evidence,
        evidence_refs=["execution:1"],
        negative_control=negative,
    )
    assert not validate_bundle_structure(bundle)
    sealed = bundle.seal(actor="validator")
    assert validate_bundle_structure(sealed)
    assert validate_replay(sealed, evidence, negative)
    assert not validate_replay(sealed, evidence, {"status": 200, "object_id": "1"})


def test_causal_validator_is_fail_closed() -> None:
    valid = {
        "causal_signal": True,
        "negative_control_complete": True,
        "evidence_refs": ["obs:causal"],
    }
    assert validate_causal_observation(valid)
    assert not validate_causal_observation({**valid, "negative_control_complete": False})
    assert not validate_causal_observation({"causal_signal": True})


def test_team_registry_is_explicit_and_artifacts_are_declared() -> None:
    spec = get_role_spec("validator")
    assert spec is not None
    assert "proof_bundle" in spec.required_inputs or "proof_bundle" in spec.emitted_artifacts
    assert validate_role_artifact("validator", {"proof_bundle": {"sealed": True}})
    assert not validate_role_artifact("validator", {"finding": "unverified"})
    assert len(team_manifest()) >= 5
