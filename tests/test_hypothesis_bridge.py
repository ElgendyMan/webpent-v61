from __future__ import annotations

from webpent.intelligence.contracts import EndpointIntelligence
from webpent.intelligence.hypothesis_bridge import build_kernel_hypotheses
from webpent.models.hypothesis import HypothesisStatus


def _endpoints() -> list[EndpointIntelligence]:
    return [
        EndpointIntelligence(
            path="http://lab.local/api/invoices/1",
            method="GET",
            auth_required=True,
            role="user",
            object="invoice",
            hypotheses=["object-authorization-boundary-candidate"],
            evidence_refs=["obs:endpoint", "obs:auth"],
        ),
        EndpointIntelligence(
            path="http://lab.local/api/invoices/1",
            method="POST",
            auth_required=True,
            role="user",
            hypotheses=["form-workflow-candidate"],
            evidence_refs=["obs:workflow"],
        ),
    ]


def test_bridge_is_stable_bounded_and_proposal_only() -> None:
    first = build_kernel_hypotheses(
        engagement_id="eng-bridge",
        endpoints=_endpoints(),
    )
    second = build_kernel_hypotheses(
        engagement_id="eng-bridge",
        endpoints=_endpoints(),
    )

    def stable_fields(item):
        return (
            str(item.id),
            item.target_url,
            item.statement,
            str(item.vuln_class),
            item.evidence_contract,
            item.request_method,
            str(item.status),
        )
    assert [stable_fields(item) for item in first] == [stable_fields(item) for item in second]
    assert len(first) == 2
    assert all(item.status == HypothesisStatus.UNEXPLORED.value for item in first)
    assert all(item.deterministic_match is False for item in first)
    assert all(item.hint_provenance == ["target_brain", "observed_endpoint"] for item in first)
    assert all(item.evidence_contract for item in first)
    assert all("evidence_needed" in item.evidence_contract for item in first)
    assert all("attack_plan" in item.evidence_contract for item in first)
    assert all("finding" not in repr(item).lower() for item in first)
    assert all("execute" not in repr(item).lower() for item in first)


def test_bridge_does_not_duplicate_existing_hypotheses() -> None:
    initial = build_kernel_hypotheses(
        engagement_id="eng-bridge",
        endpoints=_endpoints(),
    )
    repeated = build_kernel_hypotheses(
        engagement_id="eng-bridge",
        endpoints=_endpoints(),
        existing=initial,
    )

    assert repeated == []


def test_bridge_separates_engagement_stable_ids() -> None:
    first = build_kernel_hypotheses(
        engagement_id="eng-a",
        endpoints=_endpoints(),
    )
    second = build_kernel_hypotheses(
        engagement_id="eng-b",
        endpoints=_endpoints(),
    )

    assert {item.id for item in first}.isdisjoint({item.id for item in second})
