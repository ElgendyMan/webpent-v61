from __future__ import annotations

import pytest

from webpent.attack_graph.path_ranker import AttackPathRanker
from webpent.copilot.critic import LLMCritic
from webpent.copilot.explainer import LLMExplainer
from webpent.copilot.planner import LLMPlanner
from webpent.experience.store import ExperienceMemory
from webpent.knowledge.auth_model import AuthorizationModel
from webpent.knowledge.data_flow_model import DataFlowModel
from webpent.knowledge.entity_graph import EntityGraph
from webpent.knowledge.target_knowledge import (
    AuthorizationProfile,
    DataFlow,
    KnowledgeEdge,
    KnowledgeKind,
    KnowledgeNode,
    TargetKnowledgeModel,
)
from webpent.knowledge.workflow_model import WorkflowModel
from webpent.persistence.backend_capability import BackendCapabilityReport
from webpent.shared.copilot_boundary import sanitize_copilot_suggestion


def _model() -> TargetKnowledgeModel:
    model = TargetKnowledgeModel(engagement_id="eng-71")
    model.add_node(
        KnowledgeNode(
            node_id="host-1",
            kind=KnowledgeKind.HOST,
            canonical_key="host:example.test",
            confidence=0.8,
            evidence_refs=["ev-host"],
        )
    )
    model.add_node(
        KnowledgeNode(
            node_id="endpoint-1",
            kind=KnowledgeKind.ENDPOINT,
            canonical_key="endpoint:/api",
            confidence=0.6,
            evidence_refs=["ev-endpoint"],
        )
    )
    model.add_edge(
        KnowledgeEdge(
            source_id="host-1",
            target_id="endpoint-1",
            relation="serves",
            confidence=0.7,
            evidence_refs=["ev-edge"],
        )
    )
    model.authorization_profiles["user-a"] = AuthorizationProfile(
        identity_id="user-a",
        role_names=["user"],
        authorization_status="unknown",
    )
    model.data_flows.append(
        DataFlow(
            source_id="endpoint-1",
            destination_id="host-1",
            channel="http",
            observed=True,
            evidence_refs=["ev-flow"],
        )
    )
    return model


def test_knowledge_facades_are_read_only_and_evidence_preserving() -> None:
    model = _model()
    graph = EntityGraph.from_model(model)
    assert graph.neighbors("host-1") == ("endpoint-1",)
    assert "ev-edge" in graph.evidence_refs()
    assert AuthorizationModel.from_target_knowledge(model).is_authorized("user-a") is False
    assert len(DataFlowModel.from_target_knowledge(model).observed()) == 1
    assert WorkflowModel.from_target_knowledge(model).get("missing") is None


def test_path_ranker_does_not_create_paths() -> None:
    graph = {
        "edges": [
            {"id": "b", "confidence": "observed", "evidence_refs": []},
            {"id": "a", "confidence": "causal_observed", "evidence_refs": ["ev-a"]},
        ]
    }
    ranked = AttackPathRanker().rank(graph)
    assert [item["id"] for item in ranked] == ["a", "b"]
    assert AttackPathRanker().rank({}) == []


def test_experience_memory_is_engagement_scoped_and_non_authoritative() -> None:
    first = ExperienceMemory(engagement_id="eng-71", client_id="client-a")
    second = ExperienceMemory(engagement_id="eng-72", client_id="client-a")
    record = first.add_success(content="observed stable behavior", evidence_refs=["ev-1"])
    assert record is not None
    assert len(first.success_patterns()) == 1
    assert second.records == ()
    exported = first.export()
    assert exported["engagement_id"] == "eng-71"
    assert exported["authoritative"] is False


def test_copilot_planner_critic_and_explainer_remain_proposal_only() -> None:
    planner = LLMPlanner()
    proposals = planner.propose(
        {"coverage_gaps": ["auth"]},
        candidate_actions=[
            {"action_class": "information_gathering", "target_ref": "endpoint:/api"},
            {"action_class": "exploit", "target_ref": "endpoint:/api"},
        ],
    )
    assert len(proposals) == 1
    assert "finding" not in proposals[0]
    assert LLMCritic().review({"finding": {}})["accepted"] is False
    explanation = LLMExplainer().explain({"status": "candidate", "evidence_refs": ["ev-1"]})
    assert explanation["finding_authority"] is False
    assert sanitize_copilot_suggestion({"execute": True}) is None


def test_backend_capability_fails_closed_for_unqualified_postgresql() -> None:
    assert BackendCapabilityReport("sqlite:///webpent.db").as_dict()["qualified"] is True
    report = BackendCapabilityReport("postgresql://db.example/test").as_dict()
    assert report["supported"] is False
    assert report["fail_closed"] is True
    with pytest.raises(RuntimeError):
        BackendCapabilityReport("postgresql://db.example/test").assert_supported()
