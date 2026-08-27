from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import Request, urlopen

from webpent.adapters.controlled_target import (
    CONTROLLED_IDOR_CASE_ID,
    CONTROLLED_TARGET_ID,
    build_controlled_idor_registration,
    build_controlled_idor_target,
    build_controlled_target_spec,
)
from webpent.models.proof_bundle import proof_bundle_promotion_ready
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import LifecycleAuthorization, LifecycleRunContext
from webpent.shared.target_adapters import TargetAdapterRegistry


def _get_status(url: str) -> int:
    try:
        with urlopen(Request(url, method="GET"), timeout=2) as response:
            return int(response.status)
    except HTTPError as exc:
        return int(exc.code)


def _ready_target():
    target = build_controlled_idor_target()
    target.start()
    spec = build_controlled_target_spec(target.target_origin)
    target.bind_target_spec(spec)
    return target, spec


def test_controlled_target_registration_is_explicit_and_loopback_only() -> None:
    target, _spec = _ready_target()
    try:
        registration = build_controlled_idor_registration(target)
        assert registration.validate() == ()
        registry = TargetAdapterRegistry()
        registry.register(registration)
        assert (
            registry.require_live_for_origin(target.target_origin).target_id == CONTROLLED_TARGET_ID
        )
        assert not target.accepts_origin("http://127.0.0.1:9")
        assert not target.accepts_origin("https://example.com")
        assert registration.effective_manifest is not None
        assert registration.effective_manifest.allowed_scope == (target.target_origin,)
    finally:
        target.stop()
    assert not target.running


def test_reset_is_deterministic_and_get_only() -> None:
    target, _spec = _ready_target()
    try:
        first = target.state_hash
        assert target.reset() == first
        assert target.readiness()["reset_verified"] is True
        assert (
            _get_status(
                f"{target.target_origin}/controlled/resources/{target.state.owned_resource}?actor={target.state.owner_actor}"
            )
            == 200
        )
        assert (
            _get_status(
                f"{target.target_origin}/controlled/resources/{target.state.owned_resource}?actor={target.state.attacker_actor}"
            )
            == 200
        )
        assert (
            _get_status(
                f"{target.target_origin}/controlled/resources/{target.state.unrelated_resource}?actor={target.state.attacker_actor}"
            )
            == 403
        )
        assert (
            _get_status(
                f"{target.target_origin}/controlled/resources/{target.state.owned_resource}"
            )
            == 400
        )
        assert (
            _get_status(
                f"{target.target_origin}/controlled/resources/{target.state.owned_resource}"
            )
            == 400
        )
    finally:
        target.stop()


def test_generic_lifecycle_produces_target_runtime_idor_proof_and_replay() -> None:
    target, spec = _ready_target()
    try:
        registration = build_controlled_idor_registration(target)
        case = target.case_definition()
        authorization = LifecycleAuthorization(
            authorized=True,
            engagement_id=spec.engagement_id,
            allowed_origin=target.target_origin,
            actor="test-owner-approved-local-validation",
            satisfied_requirements=(
                "controlled_local_target_authorization",
                "loopback_origin",
                "get_only_causal_validation",
            ),
        )
        context = LifecycleRunContext(
            run_id="controlled-test-run-v1",
            target_id=CONTROLLED_TARGET_ID,
            case_id=CONTROLLED_IDOR_CASE_ID,
            engagement_id=spec.engagement_id,
        )
        result = GenericCaseRunner.execute_case(registration, case, authorization, context)
        verification = target._last_verification
        assert result.status == "confirmed"
        assert result.proof_bundle_ref
        assert verification is not None and verification.passed
        bundle = verification.proof_bundle
        assert bundle is not None
        assert bundle.evidence_origin == "target_runtime"
        assert bundle.target_backed is True
        assert bundle.oracle_decision == "CONFIRMED"
        assert bundle.target_identity == CONTROLLED_TARGET_ID
        assert bundle.campaign_id
        assert bundle.run_id == context.run_id
        assert bundle.vulnerability_class == "idor"
        assert bundle.sealed is True and bundle.verify_seal() is True
        assert proof_bundle_promotion_ready(bundle) is True
        replay_context = verification.evidence["replay_context"]
        assert (
            bundle.replay(
                list(verification.evidence["proof_evidence"]),
                verification.evidence["negative_control"],
                replay_context=replay_context,
            )
            is True
        )
        altered = dict(replay_context)
        altered["run_id"] = "different-run"
        assert (
            bundle.replay(
                list(verification.evidence["proof_evidence"]),
                verification.evidence["negative_control"],
                replay_context=altered,
            )
            is False
        )
        assert target.request_count == 3
    finally:
        target.stop()


def test_target_case_is_not_governance_qualification() -> None:
    target, _spec = _ready_target()
    try:
        binding = target.case(CONTROLLED_IDOR_CASE_ID)
        registration = build_controlled_idor_registration(target)
        assert binding is not None
        assert binding.scoring_status == "technical_proof_only_not_approved_scoring_case"
        assert registration.metadata["approved_scoring_case"] is False
        assert registration.metadata["qualification_effect"] is False
    finally:
        target.stop()
