from webpent.models.hypothesis import HypothesisStatus
from webpent.research_engine.campaign_hypothesis_lifecycle import CampaignHypothesisLifecycle
from webpent.research_engine.hypothesis_manager import HypothesisDraft, HypothesisManager

HYPOTHESIS_ID = "00000000-0000-0000-0000-000000000001"


def _hypothesis():
    return HypothesisManager().create(
        HypothesisDraft(
            target_id="http://127.0.0.1:18080/controlled/resource/1",
            vulnerability_class="idor",
            reasoning="Authorization boundary may expose a foreign controlled resource.",
            evidence_needed=("candidate-observation", "negative-control"),
            validation_method="compare authorized and independent control responses",
            confidence=0.4,
        ),
        engagement_id="engagement-arex-001",
        hypothesis_id=HYPOTHESIS_ID,
    )


def test_created_projection_is_advisory_and_preserves_unexplored_status():
    result = CampaignHypothesisLifecycle().project(_hypothesis(), "CREATED")

    assert result.accepted is True
    assert result.canonical_status == HypothesisStatus.UNEXPLORED.value
    assert result.advisory_only is True
    assert result.finding_created is False


def test_supported_projection_enters_investigation_without_proof_or_finding():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "SUPPORTED",
        evidence_refs=("observation:redacted-candidate",),
    )

    assert result.accepted is True
    assert result.canonical_status == HypothesisStatus.INVESTIGATING.value
    assert result.reasons == ("supporting_evidence_is_not_proof",)
    assert result.finding_created is False


def test_blocked_projection_remains_investigating_and_records_gate_reason():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "BLOCKED",
        evidence_refs=("observation:precondition-blocked",),
    )

    assert result.accepted is True
    assert result.canonical_status == HypothesisStatus.INVESTIGATING.value
    assert result.reasons == ("blocked_task_or_campaign_gate",)
    assert result.finding_created is False


def test_validated_projection_fails_closed_without_all_proof_gates():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "VALIDATED",
        causal_signal=True,
        negative_control_complete=True,
        evidence_refs=("proof:candidate",),
    )

    assert result.accepted is False
    assert result.canonical_status == HypothesisStatus.UNEXPLORED.value
    assert result.reasons == ("validation_gate_missing:central_proof",)
    assert result.finding_created is False


def test_validated_projection_requires_causal_and_negative_control():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "VALIDATED",
        central_proof=True,
        evidence_refs=("proof:candidate",),
    )

    assert result.accepted is False
    assert result.reasons == ("validation_gate_missing:causal_signal,negative_control_complete",)


def test_validated_projection_resolves_true_only_after_all_gates():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "VALIDATED",
        causal_signal=True,
        negative_control_complete=True,
        central_proof=True,
        evidence_refs=("proof:sealed-redacted-001",),
    )

    assert result.accepted is True
    assert result.canonical_status == HypothesisStatus.RESOLVED_TRUE.value
    assert result.hypothesis.evidence_refs == ["proof:sealed-redacted-001"]
    assert result.finding_created is False


def test_rejected_projection_requires_negative_control_and_evidence():
    missing_control = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "REJECTED",
        evidence_refs=("control:negative-001",),
    )
    missing_refs = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "REJECTED",
        negative_control_complete=True,
    )

    assert missing_control.accepted is False
    assert missing_control.reasons == ("rejection_gate_missing:negative_control_complete",)
    assert missing_refs.accepted is False
    assert missing_refs.reasons == ("rejection_gate_missing:evidence_refs",)


def test_rejected_projection_resolves_false_with_completed_control():
    result = CampaignHypothesisLifecycle().project(
        _hypothesis(),
        "REJECTED",
        negative_control_complete=True,
        evidence_refs=("control:negative-001",),
    )

    assert result.accepted is True
    assert result.canonical_status == HypothesisStatus.RESOLVED_FALSE.value
    assert result.finding_created is False


def test_unsupported_campaign_label_fails_closed():
    try:
        CampaignHypothesisLifecycle().project(_hypothesis(), "PROMOTED")
    except ValueError as exc:
        assert str(exc) == "unsupported_campaign_lifecycle_label"
    else:
        raise AssertionError("unsupported campaign label was accepted")
