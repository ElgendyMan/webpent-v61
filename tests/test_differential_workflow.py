from datetime import datetime, timedelta, timezone

import pytest

from webpent.shared.control_plane import IdentityProfileRef, compile_scope, evaluate_scope
from webpent.shared.differential_workflow import (
    DifferentialVariant,
    DifferentialWorkflowRunner,
)

ENGAGEMENT = "engagement-diff"
ORIGIN = "https://target.example.test"


def _scope():
    return compile_scope(
        engagement_id=ENGAGEMENT,
        root_domains=(ORIGIN,),
        created_by="test",
        approval_source="local-test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )


def _identity(identity_id: str, *, tenant: str, role: str) -> IdentityProfileRef:
    return IdentityProfileRef(
        identity_id=identity_id,
        engagement_id=ENGAGEMENT,
        email_ref=f"email://{identity_id}",
        username_ref=f"user://{identity_id}",
        role=role,
        tenant_ref=tenant,
        provenance="local-test",
    )


def _runner():
    decision = evaluate_scope(_scope(), f"{ORIGIN}/objects/1")
    return DifferentialWorkflowRunner(
        engagement_id=ENGAGEMENT,
        target_url=f"{ORIGIN}/objects/1",
        scope_decision=decision,
    )


def test_runner_emits_redacted_differential_signal_without_promotion():
    runner = _runner()
    owner = DifferentialVariant(
        label="owner",
        identity=_identity("identity-owner", tenant="tenant-a", role="owner"),
        role="owner",
        tenant_ref="tenant-a",
    )
    foreign = DifferentialVariant(
        label="foreign",
        identity=_identity("identity-foreign", tenant="tenant-b", role="member"),
        role="member",
        tenant_ref="tenant-b",
    )

    result = runner.compare(
        baseline=owner,
        variant=foreign,
        variant_kind="owner_vs_foreign",
        observe=lambda item: {
            "status": "completed",
            "response_fingerprint": "sha256:" + ("a" if item.label == "owner" else "b") * 64,
            "state_fingerprint": "sha256:" + "c" * 64,
            "evidence_refs": (f"observation://{item.label}",),
        },
        negative_control_complete=True,
        replayable=True,
    )

    assert result.differential_signal is True
    assert result.status == "differential_signal"
    assert result.negative_control_complete is True
    assert result.replayable is True
    assert result.promotion_eligible is False
    assert result.as_dict()["promotion_eligible"] is False


@pytest.mark.parametrize(
    ("kind", "baseline_role", "variant_role", "baseline_tenant", "variant_tenant"),
    [
        ("role_a_vs_role_b", "admin", "member", "tenant-a", "tenant-a"),
        ("tenant_a_vs_tenant_b", "member", "member", "tenant-a", "tenant-b"),
    ],
)
def test_runner_supports_role_and_tenant_differentials(
    kind, baseline_role, variant_role, baseline_tenant, variant_tenant
):
    runner = _runner()
    baseline = DifferentialVariant(
        label="baseline",
        identity=_identity("identity-a", tenant=baseline_tenant, role=baseline_role),
        role=baseline_role,
        tenant_ref=baseline_tenant,
    )
    variant = DifferentialVariant(
        label="variant",
        identity=_identity("identity-b", tenant=variant_tenant, role=variant_role),
        role=variant_role,
        tenant_ref=variant_tenant,
    )

    result = runner.compare(
        baseline=baseline,
        variant=variant,
        variant_kind=kind,
        observe=lambda _item: {"status": "completed", "response": {"status": 403}},
        negative_control_complete=True,
        replayable=True,
    )

    assert result.status == "no_differential_signal"
    assert result.differential_signal is False


def test_runner_blocks_without_negative_control_or_replay():
    runner = _runner()
    baseline = DifferentialVariant(
        label="baseline",
        identity=_identity("identity-a", tenant="tenant-a", role="owner"),
        role="owner",
        tenant_ref="tenant-a",
    )
    variant = DifferentialVariant(
        label="variant",
        identity=_identity("identity-b", tenant="tenant-b", role="member"),
        role="member",
        tenant_ref="tenant-b",
    )

    result = runner.compare(
        baseline=baseline,
        variant=variant,
        variant_kind="owner_vs_foreign",
        observe=lambda _item: {"response": {"status": 200}},
    )

    assert result.status == "blocked_by_precondition"
    assert result.reason == "negative_control_required"
    assert result.baseline is None
    assert result.promotion_eligible is False


def test_runner_rejects_secrets_and_cross_engagement_identities():
    runner = _runner()
    baseline = DifferentialVariant(
        label="baseline",
        identity=_identity("identity-a", tenant="tenant-a", role="owner"),
        role="owner",
        tenant_ref="tenant-a",
    )
    foreign = DifferentialVariant(
        label="foreign",
        identity=_identity("identity-b", tenant="tenant-b", role="member"),
        role="member",
        tenant_ref="tenant-b",
    )

    secret_result = runner.compare(
        baseline=baseline,
        variant=foreign,
        variant_kind="owner_vs_foreign",
        observe=lambda _item: {"cookies": ["raw-cookie"]},
        negative_control_complete=True,
        replayable=True,
    )
    assert secret_result.status == "blocked_by_precondition"
    assert secret_result.reason == "observation_rejected:ValueError"

    cross_engagement = foreign.__class__(
        label="other",
        identity=foreign.identity.model_copy(update={"engagement_id": "other-engagement"}),
        role="member",
        tenant_ref="tenant-b",
    )
    with pytest.raises(ValueError, match="differential_identity_engagement_mismatch"):
        runner.compare(
            baseline=baseline,
            variant=cross_engagement,
            variant_kind="owner_vs_foreign",
            observe=lambda _item: {"response": {"status": 403}},
            negative_control_complete=True,
            replayable=True,
        )
