from __future__ import annotations

import pytest
from pydantic import ValidationError

from webpent.intelligence.contracts import (
    ApplicationKnowledgeGraph,
    EndpointIntelligence,
    IntelligenceRisk,
    ResearchHypothesis,
    build_endpoint_hypotheses,
)
from webpent.models.findings import Severity, VulnClass
from webpent.models.hypothesis import Hypothesis


def test_endpoint_intelligence_normalises_and_deduplicates() -> None:
    endpoint = EndpointIntelligence(
        path="/api/orders/{id}",
        method="post",
        auth_required=True,
        object="order",
        hypotheses=["idor", "idor", "business_logic"],
        evidence_refs=["obs-1", "obs-1"],
    )

    assert endpoint.method == "POST"
    assert endpoint.object_name == "order"
    assert endpoint.hypotheses == ["idor", "business_logic"]
    assert endpoint.evidence_refs == ["obs-1"]


def test_knowledge_graph_merges_endpoint_without_downgrading_risk() -> None:
    graph = ApplicationKnowledgeGraph(engagement_id="eng-1")
    graph.add_endpoint(
        EndpointIntelligence(path="/api/orders/{id}", method="GET", risk=IntelligenceRisk.HIGH)
    )
    graph.add_endpoint(
        EndpointIntelligence(
            path="/api/orders/{id}",
            method="get",
            risk=IntelligenceRisk.LOW,
            evidence_refs=["obs-2"],
        )
    )

    endpoint = graph.endpoints["GET:/api/orders/{id}"]
    assert endpoint.risk == IntelligenceRisk.HIGH
    assert endpoint.evidence_refs == ["obs-2"]
    assert graph.as_dict()["engagement_id"] == "eng-1"


def test_research_hypothesis_adapts_to_kernel_without_confirmation() -> None:
    hypothesis = ResearchHypothesis(
        target_url="https://example.invalid/api/orders/1",
        reason="The object boundary may be missing for an authenticated caller.",
        evidence_needed=["two identities", "negative control"],
        attack_plan=["compare owner and non-owner"],
        risk=Severity.HIGH,
        confidence=0.7,
        vuln_class=VulnClass.IDOR,
    )

    kernel = hypothesis.to_kernel_hypothesis()
    assert isinstance(kernel, Hypothesis)
    assert kernel.vuln_class == VulnClass.IDOR
    assert kernel.confidence_score == pytest.approx(0.7)
    assert kernel.evidence_contract is not None
    assert kernel.evidence_contract["evidence_needed"] == ["two identities", "negative control"]
    assert kernel.status.value == "unexplored"


def test_endpoint_hypotheses_are_bounded_and_explainable() -> None:
    hypotheses = build_endpoint_hypotheses(
        EndpointIntelligence(
            path="/api/orders/{id}", method="PATCH", auth_required=True, object="order"
        ),
        target_url="https://example.invalid/api/orders/1",
    )

    assert {item.vuln_class for item in hypotheses} == {VulnClass.IDOR, VulnClass.UNKNOWN}
    assert all(item.evidence_needed for item in hypotheses)
    assert all(item.attack_plan for item in hypotheses)
    assert all(0.0 <= item.confidence <= 1.0 for item in hypotheses)


def test_endpoint_rejects_unknown_fields_and_oversized_hypothesis_pool() -> None:
    with pytest.raises(ValidationError):
        EndpointIntelligence(path="/", unexpected="must fail")
    with pytest.raises(ValidationError):
        EndpointIntelligence(path="/", hypotheses=[str(index) for index in range(9)])


def test_non_object_authenticated_endpoint_does_not_invent_idor() -> None:
    hypotheses = build_endpoint_hypotheses(
        EndpointIntelligence(path="/api/profile", method="GET", auth_required=True),
        target_url="https://example.invalid/api/profile",
    )

    assert all(item.vuln_class != VulnClass.IDOR for item in hypotheses)
