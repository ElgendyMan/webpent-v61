from webpent.agents.team import get_role_spec, team_manifest, validate_role_artifact
from webpent.asros.quality_controller import (
    QualityReviewStatus,
    ResearchQualityController,
)


def _hypothesis(**overrides):
    value = {
        "id": "hyp-quality-1",
        "reason": "Object ownership enforcement is uncertain.",
        "affected_asset": "object",
        "attack_plan": ("compare owner and non-owner read-only responses",),
        "evidence_refs": ("obs:object-id",),
    }
    value.update(overrides)
    return value


def test_pre_execution_review_challenges_weak_hypothesis_fail_closed():
    controller = ResearchQualityController()
    review = controller.review_before(
        hypothesis={"id": "hyp-weak", "reason": "maybe", "affected_asset": "object"},
        argument_chain=None,
        scope_allowed=False,
    )

    assert review.status is QualityReviewStatus.BLOCKED
    assert review.can_execute is False
    assert review.can_create_findings is False
    assert review.can_override_policy is False
    assert {issue.code for issue in review.issues} >= {
        "scope_denied",
        "validation_plan_missing",
        "argument_chain_missing",
    }


def test_pre_execution_review_accepts_well_formed_proposal_only_for_review():
    review = ResearchQualityController().review_before(
        hypothesis=_hypothesis(),
        argument_chain={"chain_id": "argument:1"},
    )

    assert review.status is QualityReviewStatus.ACCEPTED_FOR_REVIEW
    assert review.score >= 0.55
    assert review.advisory_only is True
    assert review.can_execute is False
    assert review.can_create_findings is False


def test_post_execution_requires_observations_causal_control_and_proof():
    controller = ResearchQualityController()
    insufficient = controller.review_after(
        hypothesis_id="hyp-quality-1",
        evidence_refs=("obs:one",),
        observation_count=1,
        causal_oracle_passed=True,
        negative_control_passed=False,
        proof_sealed=False,
        proof_replayable=False,
    )

    assert insufficient.status is QualityReviewStatus.INSUFFICIENT
    assert insufficient.causal_proof_present is True
    assert insufficient.negative_control_present is False
    assert insufficient.can_approve_vulnerability is False
    assert "negative_control_missing" in {issue.code for issue in insufficient.issues}


def test_post_execution_accepts_complete_evidence_but_never_approves_vulnerability():
    review = ResearchQualityController().review_after(
        hypothesis_id="hyp-quality-1",
        evidence_refs=("obs:candidate", "obs:control", "proof:sealed"),
        causal_oracle_passed=True,
        negative_control_passed=True,
        proof_sealed=True,
        proof_replayable=True,
        observation_count=2,
        claim="Causal evidence is sufficient for central verification review.",
    )

    assert review.status is QualityReviewStatus.ACCEPTED_FOR_REVIEW
    assert review.evidence_quality_score > 0.5
    assert review.overclaim_detected is False
    assert review.can_approve_vulnerability is False
    assert review.can_override_oracle is False
    assert review.can_override_policy is False


def test_post_execution_blocks_overclaiming_and_redacts_sensitive_claims():
    review = ResearchQualityController().review_after(
        hypothesis_id="hyp-quality-1",
        evidence_refs=("obs:one",),
        causal_oracle_passed=True,
        negative_control_passed=True,
        proof_sealed=True,
        proof_replayable=True,
        observation_count=1,
        claim="confirmed vulnerability with query_token=secret-value",
    )

    assert review.status is QualityReviewStatus.BLOCKED
    assert review.overclaim_detected is True
    assert review.can_approve_vulnerability is False
    assert "overclaim_detected" in {issue.code for issue in review.issues}
    assert all("secret-value" not in issue.message for issue in review.issues)


def test_asros_specialist_roles_are_advisory_and_cannot_emit_authority():
    names = {
        "application_analyst",
        "authorization_analyst",
        "adversarial_reasoner",
        "evidence_scientist",
        "research_manager",
    }
    manifest = {item["role"]: item for item in team_manifest()}
    assert names <= manifest.keys()
    for name in names:
        spec = get_role_spec(name)
        assert spec is not None
        assert spec.advisory_only is True
        assert spec.can_execute is False
        assert spec.can_create_findings is False
        assert spec.can_override_oracle is False
        assert spec.can_override_policy is False
        assert validate_role_artifact(name, {spec.emitted_artifacts[0]: "proposal"}) is True
        assert validate_role_artifact(name, {"finding": "x"}) is False
        assert validate_role_artifact(name, {"policy_override": True}) is False
