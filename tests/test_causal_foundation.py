from __future__ import annotations

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.proof_oracles import (
    CausalDecision,
    CausalObservation,
    CausalOracleContract,
    OracleEngine,
    OracleFamily,
)
from webpent.shared.verifier import _target_fingerprint, verify_replay_evidence

TARGET_URL = "https://lab.example.test/object"


def _digest(letter: str) -> str:
    return f"sha256:{letter * 64}"


def _observation(
    role: str,
    ref: str,
    fingerprint: str,
    *,
    holds: bool,
    violated: bool = False,
    state: str = "owner",
) -> CausalObservation:
    return CausalObservation(
        observation_ref=ref,
        role=role,
        semantic_fingerprint=fingerprint,
        request_digest=_digest({"baseline": "a", "candidate": "b", "negative_control": "c"}[role]),
        response_digest=_digest({"baseline": "d", "candidate": "e", "negative_control": "f"}[role]),
        signals={
            "invariant_holds": holds,
            "invariant_violated": violated,
            "resource_state": state,
        },
        target_backed=True,
    )


def _contract(
    *, candidate_holds: bool, candidate_violated: bool, candidate_state: str = "foreign"
) -> CausalOracleContract:
    return CausalOracleContract(
        family=OracleFamily.IDOR,
        baseline=_observation(
            "baseline", "obs-baseline", "owner-resource", holds=True, state="owner"
        ),
        candidate=_observation(
            "candidate",
            "obs-candidate",
            "owner-resource" if candidate_holds else candidate_state,
            holds=candidate_holds,
            violated=candidate_violated,
            state="owner" if candidate_holds else candidate_state,
        ),
        negative_control=_observation(
            "negative_control", "obs-control", "denied-resource", holds=True, state="denied"
        ),
        expected_invariant="A non-owner cannot read an object owned by another identity.",
        violated_invariant="The candidate read returns the foreign object to a non-owner.",
    )


def test_causal_oracle_confirms_only_semantic_three_way_violation():
    result = OracleEngine.evaluate_experiment(
        _contract(candidate_holds=False, candidate_violated=True)
    )

    assert result.decision == CausalDecision.CONFIRMED
    assert result.reviewable is True
    assert result.invariant_analysis["candidate_differs_from_baseline"] is True
    assert result.invariant_analysis["candidate_differs_from_negative_control"] is True


def test_causal_oracle_clean_requires_invariant_preservation():
    result = OracleEngine.evaluate_experiment(
        _contract(candidate_holds=True, candidate_violated=False, candidate_state="owner-resource")
    )

    assert result.decision == CausalDecision.CLEAN
    assert result.causal_signal is False


def test_causal_oracle_rejects_transport_only_observations():
    base = {
        "observation_ref": "obs-base",
        "role": "baseline",
        "semantic_fingerprint": "same",
        "request_digest": _digest("a"),
        "response_digest": _digest("b"),
        "signals": {"status_code": 200},
    }
    candidate = {
        **base,
        "observation_ref": "obs-candidate",
        "role": "candidate",
        "request_digest": _digest("c"),
    }
    control = {
        **base,
        "observation_ref": "obs-control",
        "role": "negative_control",
        "request_digest": _digest("d"),
    }
    contract = {
        "family": "idor",
        "baseline": base,
        "candidate": candidate,
        "negative_control": control,
        "expected_invariant": "owner boundary holds",
        "violated_invariant": "owner boundary is violated",
    }

    result = OracleEngine.evaluate_experiment(contract)

    assert result.decision == CausalDecision.BLOCKED
    assert "baseline_semantic_signal_missing" in result.missing
    assert "candidate_semantic_signal_missing" in result.missing


def test_causal_oracle_is_inconclusive_when_predicate_is_not_proven():
    result = OracleEngine.evaluate_experiment(
        _contract(candidate_holds=False, candidate_violated=False)
    )

    assert result.decision == CausalDecision.INCONCLUSIVE
    assert result.causal_signal is False


def _finding() -> Finding:
    return Finding(
        title="Offline causal fixture finding",
        severity=Severity.HIGH,
        description="Synthetic target-backed verifier fixture.",
        tool_name="fixture.causal.validator",
        url=TARGET_URL,
        vuln_class=VulnClass.IDOR,
    )


def _target_mapping(
    result: CausalOracleContract,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    target_fp = _target_fingerprint(TARGET_URL)
    values = {}
    for observation in (result.baseline, result.candidate, result.negative_control):
        values[observation.role] = {
            "target_backed": True,
            "evidence_origin": "target_runtime",
            "observation_role": observation.role,
            "target_fingerprint": target_fp,
            "request_digest": observation.request_digest,
            "response_digest": observation.response_digest,
            "semantic_fingerprint": observation.semantic_fingerprint,
            "invariant_holds": observation.signals.get("invariant_holds", False),
            "invariant_violated": observation.signals.get("invariant_violated", False),
        }
    return values["baseline"], values["candidate"], values["negative_control"]


def test_vnext_verifier_seals_and_replays_typed_decision():
    contract = _contract(candidate_holds=False, candidate_violated=True)
    oracle_result = OracleEngine.evaluate_experiment(contract)
    baseline, candidate, control = _target_mapping(contract)

    result = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=control,
        causal_result=oracle_result,
        validator_id="fixture.causal.validator",
        validator_version="2.0",
        causal_basis=oracle_result.reason,
        engagement_id="engagement-causal-vnext",
        hypothesis_id="hypothesis-causal-vnext",
        scope_context={"allowed_origin": "https://lab.example.test"},
        identity_context={"owner": "synthetic-owner", "requester": "synthetic-requester"},
        replay_metadata={"replayable": True},
        require_target_backed=True,
        campaign_id="campaign-causal-vnext",
        run_id="run-causal-vnext",
        vulnerability_class="idor",
        target_identity="target:lab.example.test",
        target_context_hash="a" * 64,
    )

    assert result.passed is True
    assert result.proof_bundle is not None
    assert result.proof_bundle.oracle_decision == "CONFIRMED"
    assert result.proof_bundle.verify_seal() is True
    replay_context = result.evidence["promotion_guard"]["replay_context"]
    assert (
        result.proof_bundle.replay(
            [
                result.evidence["baseline"],
                result.evidence["candidate"],
                result.evidence["negative_control"],
            ],
            result.evidence["negative_control"],
            replay_context=replay_context,
        )
        is True
    )

    changed_oracle = dict(replay_context, oracle_decision="CLEAN")
    changed_refs = dict(replay_context, evidence_refs=("changed:baseline",))
    changed_digest = dict(replay_context, sealed_digest="sha256:" + "0" * 64)
    for changed_context in (changed_oracle, changed_refs, changed_digest):
        assert (
            result.proof_bundle.replay(
                [
                    result.evidence["baseline"],
                    result.evidence["candidate"],
                    result.evidence["negative_control"],
                ],
                result.evidence["negative_control"],
                replay_context=changed_context,
            )
            is False
        )


def test_vnext_verifier_withholds_inconclusive_and_blocked():
    for contract in (
        _contract(candidate_holds=False, candidate_violated=False),
        {
            "family": "idor",
            "baseline": _contract(
                candidate_holds=False, candidate_violated=True
            ).baseline.model_dump(),
            "candidate": {
                **_contract(candidate_holds=False, candidate_violated=True).candidate.model_dump(),
                "signals": {"status_code": 302},
            },
            "negative_control": _contract(
                candidate_holds=False, candidate_violated=True
            ).negative_control.model_dump(),
            "expected_invariant": "owner boundary holds",
            "violated_invariant": "owner boundary is violated",
        },
    ):
        oracle_result = OracleEngine.evaluate_experiment(contract)
        assert oracle_result.decision in {CausalDecision.INCONCLUSIVE, CausalDecision.BLOCKED}
        baseline, candidate, control = _target_mapping(
            contract
            if isinstance(contract, CausalOracleContract)
            else CausalOracleContract.model_validate(contract)
        )
        result = verify_replay_evidence(
            _finding(),
            baseline=baseline,
            candidate=candidate,
            negative_control=control,
            causal_result=oracle_result,
            validator_id="fixture.causal.validator",
            validator_version="2.0",
            causal_basis=oracle_result.reason,
            engagement_id="engagement-causal-vnext",
            scope_context={"allowed_origin": "https://lab.example.test"},
            identity_context={"session": "synthetic"},
            require_target_backed=True,
        )
        assert result.passed is False
        assert result.proof_bundle is None
        assert result.reason.startswith("causal_oracle_")


def test_target_verifier_rejects_explicit_offline_origin():
    contract = _contract(candidate_holds=False, candidate_violated=True)
    oracle_result = OracleEngine.evaluate_experiment(contract)
    baseline, candidate, control = _target_mapping(contract)
    for observation in (baseline, candidate, control):
        observation["evidence_origin"] = "offline_fixture"

    result = verify_replay_evidence(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=control,
        causal_result=oracle_result,
        validator_id="fixture.causal.validator",
        validator_version="2.0",
        causal_basis=oracle_result.reason,
        engagement_id="engagement-origin-isolation",
        scope_context={"allowed_origin": "https://lab.example.test"},
        identity_context={"session": "synthetic"},
        require_target_backed=True,
    )

    assert result.passed is False
    assert result.proof_bundle is None
    assert result.reason == "offline_fixture_cannot_be_target_backed"


def test_offline_vnext_bundle_cannot_promote():
    contract = _contract(candidate_holds=False, candidate_violated=True)
    oracle_result = OracleEngine.evaluate_experiment(contract)
    from webpent.models.proof_bundle import build_proof_bundle, proof_bundle_promotion_ready

    bundle = build_proof_bundle(
        engagement_id="engagement-origin-isolation",
        finding_id="finding-offline",
        hypothesis_id="hypothesis-offline",
        target_fingerprint="sha256:" + "a" * 64,
        evidence=[{"origin": "offline_fixture"}],
        evidence_refs=["offline:baseline", "offline:candidate", "offline:control"],
        negative_control={"origin": "offline_fixture"},
        baseline={"origin": "offline_fixture"},
        request_evidence=[{"role": "candidate"}],
        response_evidence=[{"role": "candidate"}],
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        target_backed=False,
        negative_control_independent=True,
        validator_id="fixture.causal.validator",
        validator_version="2.0",
        replay_metadata={"replayable": True},
        oracle_decision="CONFIRMED",
        invariant_analysis=oracle_result.invariant_analysis,
        validator_result=oracle_result.model_dump(mode="json"),
        evidence_origin="offline_fixture",
    ).seal(actor="test")

    assert bundle.evidence_origin == "offline_fixture"
    assert bundle.verify_seal() is True
    assert proof_bundle_promotion_ready(bundle) is False
