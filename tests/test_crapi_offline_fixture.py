from __future__ import annotations

from webpent.adapters.crapi.context_provider import (
    CrAPIObjectFixtureProvider,
    CrAPISyntheticSessionProvider,
    crapi_scope,
)
from webpent.shared.proof_oracles import (
    CausalDecision,
    CausalObservation,
    CausalOracleContract,
    OracleEngine,
    OracleFamily,
)
from webpent.shared.target_context import ContextRole, FixtureRequest, IdentityRequest


def _sessions():
    provider = CrAPISyntheticSessionProvider()
    scope = crapi_scope("campaign-crapi-offline", "run-crapi-offline")
    owner = provider.create_synthetic_context(
        IdentityRequest(scope, "identity-owner", "synthetic-owner")
    )
    requester = provider.create_synthetic_context(
        IdentityRequest(scope, "identity-requester", "synthetic-requester")
    )
    return scope, owner, requester


def test_crapi_fixture_owner_requester_and_candidate_are_deterministic():
    scope, owner, requester = _sessions()
    provider = CrAPIObjectFixtureProvider()
    fixture = provider.provision(
        FixtureRequest(
            scope,
            "crapi-object-fixture",
            ContextRole.CANDIDATE,
            metadata={
                "owner_id": "synthetic-owner",
                "requester_id": "synthetic-requester",
                "object_id": "synthetic-object",
            },
        )
    )
    model = provider.get_ownership_model(fixture)
    assert model is not None

    owner_result = model.evaluate_access(owner)
    requester_result = model.evaluate_access(requester)
    candidate_result = model.evaluate_access(requester, simulate_unauthorized_access=True)

    assert owner_result["access_allowed"] is True
    assert owner_result["invariant_holds"] is True
    assert requester_result["access_denied"] is True
    assert requester_result["invariant_holds"] is True
    assert candidate_result["access_allowed"] is True
    assert candidate_result["invariant_violated"] is True
    assert fixture.state_hash == model.state_hash
    assert "token" not in str(candidate_result).lower()
    assert "password" not in str(candidate_result).lower()


def test_crapi_fixture_snapshot_restore_and_reset_verify_state_hash():
    scope, _, _ = _sessions()
    provider = CrAPIObjectFixtureProvider()
    fixture = provider.provision(
        FixtureRequest(scope, "crapi-reset-fixture", ContextRole.CANDIDATE)
    )
    snapshot = provider.snapshot(fixture)

    assert snapshot.state_hash == fixture.state_hash
    assert provider.reset(fixture) is True
    assert provider.restore(snapshot).state_hash == fixture.state_hash


def test_crapi_offline_observations_feed_typed_oracle_without_target_claim():
    scope, owner, requester = _sessions()
    provider = CrAPIObjectFixtureProvider()
    fixture = provider.provision(
        FixtureRequest(
            scope,
            "crapi-oracle-fixture",
            ContextRole.CANDIDATE,
            metadata={"owner_id": "synthetic-owner", "requester_id": "synthetic-requester"},
        )
    )
    model = provider.get_ownership_model(fixture)
    assert model is not None

    def observation(role: str, session, simulated: bool, ref: str):
        signal = model.evaluate_access(session, simulate_unauthorized_access=simulated)
        return CausalObservation(
            observation_ref=ref,
            role=role,
            semantic_fingerprint=f"{signal['resource_state']}:{signal['access_allowed']}",
            request_digest=f"sha256:{ref[0] * 64}",
            response_digest=f"sha256:{ref[-1] * 64}",
            signals=signal,
            target_backed=False,
        )

    contract = CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=observation("baseline", owner, False, "a1"),
        candidate=observation("candidate", requester, True, "b2"),
        negative_control=observation("negative_control", requester, False, "c3"),
        expected_invariant="requester cannot access owner object",
        violated_invariant="requester access is allowed for the owner object",
    )
    result = OracleEngine.evaluate_experiment(contract)

    assert result.decision == CausalDecision.CONFIRMED
    assert result.baseline.target_backed is False
    assert result.candidate.target_backed is False
    assert result.negative_control.target_backed is False
