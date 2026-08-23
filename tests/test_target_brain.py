from __future__ import annotations

import pytest

from webpent.intelligence.contracts import EndpointIntelligence
from webpent.intelligence.target_brain import build_target_brain
from webpent.knowledge.target_knowledge import (
    AuthorizationProfile,
    KnowledgeKind,
    KnowledgeNode,
    TargetKnowledgeModel,
    WorkflowState,
)


def _knowledge(engagement_id: str = "eng-main") -> TargetKnowledgeModel:
    model = TargetKnowledgeModel(engagement_id=engagement_id)
    model.add_node(
        KnowledgeNode(
            node_id="host:app",
            kind=KnowledgeKind.HOST,
            canonical_key="https://app.local",
            confidence=0.9,
            evidence_refs=["obs:host"],
        )
    )
    model.add_node(
        KnowledgeNode(
            node_id="identity:user",
            kind=KnowledgeKind.IDENTITY,
            canonical_key="user",
            confidence=0.8,
            evidence_refs=["obs:identity"],
        )
    )
    model.add_node(
        KnowledgeNode(
            node_id="object:invoice",
            kind=KnowledgeKind.OBJECT,
            canonical_key="invoice",
            confidence=0.7,
            evidence_refs=["obs:object"],
        )
    )
    model.authorization_profiles["user"] = AuthorizationProfile(
        identity_id="user",
        role_names=["member"],
        observed_capabilities=["read_invoice"],
        evidence_refs=["obs:identity"],
    )
    model.workflows["invoice"] = WorkflowState(
        workflow_id="invoice",
        name="invoice workflow",
        states=["draft", "paid"],
        evidence_refs=["obs:workflow"],
    )
    return model


def test_target_brain_is_bounded_and_evidence_linked() -> None:
    snapshot = build_target_brain(
        engagement_id="eng-main",
        knowledge=_knowledge(),
        endpoints=[
            EndpointIntelligence(
                path="/api/invoices/{id}",
                method="get",
                auth_required=True,
                object_name="invoice",
                evidence_refs=["obs:endpoint"],
            )
        ],
    )

    assert snapshot.endpoint_count == 1
    assert snapshot.host_count == 1
    assert snapshot.identity_count == 1
    assert snapshot.object_count == 1
    assert snapshot.workflow_count == 1
    assert snapshot.coverage_gaps == ["no_data_flow_observations"]
    assert snapshot.knowledge_gaps == ["role_model_unknown"]
    assert snapshot.evidence_refs == [
        "obs:endpoint",
        "obs:host",
        "obs:identity",
        "obs:object",
        "obs:workflow",
    ]
    assert snapshot.confidence == 0.75
    assert "finding" not in snapshot.as_dict()


def test_target_brain_rejects_cross_engagement_knowledge() -> None:
    with pytest.raises(ValueError, match="engagement_id"):
        build_target_brain(
            engagement_id="eng-other",
            knowledge=_knowledge("eng-main"),
        )


def test_empty_observations_are_explicit_gaps() -> None:
    snapshot = build_target_brain(
        engagement_id="eng-empty",
        knowledge=TargetKnowledgeModel(engagement_id="eng-empty"),
    )

    assert snapshot.coverage_gaps == [
        "no_endpoint_observations",
        "no_authorization_profiles",
        "no_workflow_observations",
        "no_data_flow_observations",
    ]
    assert snapshot.knowledge_gaps == [
        "host_identity_unknown",
        "object_model_unknown",
        "role_model_unknown",
    ]
    assert snapshot.confidence == 0.0
