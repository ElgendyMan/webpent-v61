from __future__ import annotations

import pytest

from webpent.rta import (
    DiscoveredSurface,
    DiscoverySnapshot,
    HttpObservation,
    HttpRequestSpec,
    RtaAssessment,
    RtaCase,
    RtaScope,
    SyntheticAuthContext,
)


def test_scope_and_synthetic_context_are_loopback_only() -> None:
    scope = RtaScope(campaign_id="rta-test")
    scope.validate()
    context = SyntheticAuthContext(
        identity_id="user-a",
        role="viewer",
        tenant_id="tenant-a",
        session_handle="synthetic:session-a",
        permissions=("resource:read",),
    )
    context.validate()


def test_external_scope_real_credentials_and_mutation_are_blocked() -> None:
    with pytest.raises(ValueError):
        RtaScope(campaign_id="bad", allowed_hosts=("evil.example",)).validate()
    with pytest.raises(ValueError):
        RtaScope(campaign_id="bad", real_credentials_allowed=True).validate()
    with pytest.raises(ValueError):
        HttpRequestSpec(method="POST", path="/transfer", state_changing=True).validate()
    with pytest.raises(ValueError):
        SyntheticAuthContext("u", "viewer", "t", "real-cookie").validate()


def test_discovery_snapshot_requires_redacted_loopback_observations() -> None:
    request = HttpRequestSpec(method="GET", path="/api/resources/{id}", auth_context_id="user-a")
    observation = HttpObservation(
        request=request,
        status_code=200,
        response_content_type="application/json",
        response_digest="sha256:response",
        semantic_facts=("object_reference",),
    )
    snapshot = DiscoverySnapshot(
        target_id="rta-target-a",
        runtime_digest="sha256:runtime-a",
        surfaces=(DiscoveredSurface("GET", "/api/resources/{id}", ("id",), True),),
        observations=(observation,),
    )
    snapshot.validate()


def test_assessment_cannot_open_governance_effects() -> None:
    case = RtaCase(
        case_id="rta-a-idor",
        target_id="rta-target-a",
        vulnerability_class="idor",
        oracle_id="oracle:object-ownership",
        negative_control_id="control:rta-a-idor",
    )
    assessment = RtaAssessment(
        campaign_id="rta-test",
        target_id="rta-target-a",
        discovered_surfaces=1,
        observations=(),
        cases=(case,),
    )
    assessment.validate()

    with pytest.raises(ValueError):
        RtaAssessment(
            campaign_id="rta-test",
            target_id="rta-target-a",
            discovered_surfaces=1,
            observations=(),
            cases=(),
            governance={"qualification_effect": True},
        ).validate()
