from webpent.knowledge.target_knowledge import (
    AuthorizationProfile,
    KnowledgeEdge,
    KnowledgeKind,
    KnowledgeNode,
    TargetKnowledgeModel,
    WorkflowState,
)
from webpent.models.findings import VulnClass
from webpent.shared.security_reasoners import (
    AuthenticationReasoner,
    AuthorizationReasoner,
    BusinessLogicReasoner,
)


def _knowledge() -> TargetKnowledgeModel:
    return TargetKnowledgeModel(
        engagement_id="engagement:reasoners",
        nodes={
            "identity-a": KnowledgeNode(
                node_id="identity-a",
                kind=KnowledgeKind.IDENTITY,
                canonical_key="identity-a-fingerprint",
                confidence=0.9,
                evidence_refs=["obs:identity-a"],
                metadata={"role": "member"},
            ),
            "identity-b": KnowledgeNode(
                node_id="identity-b",
                kind=KnowledgeKind.IDENTITY,
                canonical_key="identity-b-fingerprint",
                confidence=0.8,
                evidence_refs=["obs:identity-b"],
                metadata={"role": "member"},
            ),
            "object-order": KnowledgeNode(
                node_id="object-order",
                kind=KnowledgeKind.OBJECT,
                canonical_key="object-order-fingerprint",
                confidence=0.9,
                evidence_refs=["obs:order"],
                metadata={"object_type": "order", "url": "http://lab.local/orders/1"},
            ),
            "endpoint-approve": KnowledgeNode(
                node_id="endpoint-approve",
                kind=KnowledgeKind.ENDPOINT,
                canonical_key="endpoint-approve-fingerprint",
                confidence=0.7,
                evidence_refs=["obs:approve"],
                metadata={"method": "POST", "url": "http://lab.local/orders/approve"},
            ),
        },
        edges=[
            KnowledgeEdge(
                source_id="identity-a",
                target_id="object-order",
                relation="OWNS",
                confidence=0.9,
                evidence_refs=["obs:ownership"],
            ),
            KnowledgeEdge(
                source_id="workflow-approval",
                target_id="endpoint-approve",
                relation="CONTAINS",
                confidence=0.8,
                evidence_refs=["obs:workflow-endpoint"],
            ),
        ],
        workflows={
            "workflow-approval": WorkflowState(
                workflow_id="workflow-approval",
                name="order approval",
                required_role="approver",
                states=["pending", "approved"],
                transitions=[
                    {
                        "method": "POST",
                        "endpoint": "http://lab.local/orders/approve",
                        "from_state": "pending",
                        "to_state": "approved",
                    }
                ],
                identity_refs=["identity-a"],
                evidence_refs=["obs:workflow"],
                confidence=0.8,
            )
        },
        authorization_profiles={
            "identity-a": AuthorizationProfile(
                identity_id="identity-a",
                role_names=["member"],
                authorization_status="observed",
                evidence_refs=["obs:identity-a"],
            ),
            "identity-b": AuthorizationProfile(
                identity_id="identity-b",
                role_names=["member"],
                authorization_status="observed",
                evidence_refs=["obs:identity-b"],
            ),
        },
    )


def test_security_reasoners_are_proposal_only_and_evidence_linked() -> None:
    knowledge = _knowledge()
    authorization = AuthorizationReasoner().propose(knowledge)
    business_logic = BusinessLogicReasoner().propose(knowledge)
    authentication = AuthenticationReasoner().propose(
        {
            "engagement_id": "engagement:reasoners",
            "lifecycle_observations": ["register", "login", "session", "logout"],
            "evidence_refs": ["obs:auth-lifecycle"],
        }
    )

    proposals = [*authorization, *business_logic, *authentication]
    assert proposals
    assert {item.reasoner for item in proposals} == {
        "authorization",
        "business_logic",
        "authentication",
    }
    assert all(item.execution_mode == "proposal_only" for item in proposals)
    assert all(item.requires_action_authority is True for item in proposals)
    assert all(item.evidence_refs for item in proposals)
    assert all(item.prerequisites for item in proposals)
    assert all(0.0 <= item.confidence <= 1.0 for item in proposals)
    assert all(not hasattr(item, "request") for item in proposals)

    assert any(item.vuln_class == VulnClass.IDOR.value for item in authorization)
    assert any(
        item.vuln_class == VulnClass.RACE_CONDITION.value
        for item in business_logic
    )
    assert any(item.vuln_class == VulnClass.AUTH_BYPASS.value for item in authentication)


def test_reasoners_fail_closed_without_observations() -> None:
    assert AuthorizationReasoner().propose(TargetKnowledgeModel(engagement_id="empty")) == []
    assert BusinessLogicReasoner().propose(TargetKnowledgeModel(engagement_id="empty")) == []
    assert AuthenticationReasoner().propose({"engagement_id": "empty"}) == []
