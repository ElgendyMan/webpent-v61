from __future__ import annotations

import pytest
from pydantic import ValidationError

from webpent.asros.knowledge_graph import (
    KnowledgeEdge,
    KnowledgeEdgeKind,
    KnowledgeNode,
    KnowledgeNodeKind,
    VulnerabilityKnowledgeGraph,
)
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory


def _graph() -> VulnerabilityKnowledgeGraph:
    nodes = (
        KnowledgeNode(
            node_id="class-idor",
            kind=KnowledgeNodeKind.VULNERABILITY_CLASS,
            label="authorization boundary weakness",
            target_id="controlled-loopback",
            evidence_refs=("manifest-ref",),
        ),
        KnowledgeNode(
            node_id="pattern-object-access",
            kind=KnowledgeNodeKind.ATTACK_PATTERN,
            label="cross-owner object access",
            target_id="controlled-loopback",
            evidence_refs=("manifest-ref",),
        ),
        KnowledgeNode(
            node_id="strategy-negative-control",
            kind=KnowledgeNodeKind.VALIDATION_STRATEGY,
            label="independent negative control",
            target_id="controlled-loopback",
            evidence_refs=("oracle-ref",),
        ),
    )
    edges = (
        KnowledgeEdge(
            edge_id="edge-pattern-strategy",
            kind=KnowledgeEdgeKind.DISCOVERED_BY,
            source_id="pattern-object-access",
            target_id="strategy-negative-control",
            evidence_refs=("oracle-ref",),
        ),
    )
    return VulnerabilityKnowledgeGraph(
        target_id="controlled-loopback",
        nodes=nodes,
        edges=edges,
    )


def test_graph_resolves_related_nodes_and_validation_strategy() -> None:
    graph = _graph()

    assert graph.related_node_ids("pattern-object-access") == ("strategy-negative-control",)
    strategies = graph.candidate_validation_strategies("pattern-object-access")
    assert [item.node_id for item in strategies] == ["strategy-negative-control"]
    assert len(graph.content_hash()) == 64
    assert graph.authoritative is False
    assert graph.execution_capability is False


def test_graph_rejects_missing_edges_duplicate_nodes_and_scope_drift() -> None:
    with pytest.raises(ValidationError, match="endpoint_missing"):
        VulnerabilityKnowledgeGraph(
            target_id="controlled-loopback",
            nodes=(
                KnowledgeNode(
                    node_id="node-one",
                    kind=KnowledgeNodeKind.ATTACK_PATTERN,
                    label="pattern",
                    target_id="controlled-loopback",
                    evidence_refs=("ref",),
                ),
            ),
            edges=(
                KnowledgeEdge(
                    edge_id="edge-one",
                    kind=KnowledgeEdgeKind.COMMONLY_RELATED,
                    source_id="node-one",
                    target_id="missing-node",
                    evidence_refs=("ref",),
                ),
            ),
        )
    with pytest.raises(ValidationError, match="scope_mismatch"):
        VulnerabilityKnowledgeGraph(
            target_id="controlled-loopback",
            nodes=(
                KnowledgeNode(
                    node_id="node-one",
                    kind=KnowledgeNodeKind.ATTACK_PATTERN,
                    label="pattern",
                    target_id="other-target",
                    evidence_refs=("ref",),
                ),
            ),
        )


def test_researcher_memory_categories_are_scoped_and_redacted() -> None:
    first = SecurityReasoningMemory(engagement_id="eng-1", target_id="target-a")
    second = SecurityReasoningMemory(engagement_id="eng-1", target_id="target-b")
    secret = "https://127.0.0.1/object?token=super-secret-value"

    record = first.remember_research(
        category="failed_path",
        content=secret,
        source_ref="decision:1",
        evidence_refs=("evidence:1",),
    )
    assert record is not None
    summary = first.researcher_summary("failed")
    assert summary["isolated"] is True
    assert summary["scope"] == "eng-1:target-a"
    assert len(summary["items"]["failed_path"]) == 1
    assert "super-secret-value" not in summary["items"]["failed_path"][0]["content"]
    assert second.researcher_summary("failed")["items"]["failed_path"] == []


def test_researcher_memory_rejects_unknown_category_and_authority() -> None:
    memory = SecurityReasoningMemory(engagement_id="eng-1", target_id="target-a")
    with pytest.raises(ValueError, match="unsupported_researcher_memory_category"):
        memory.remember_research(category="finding_approval", content="not allowed")
    summary = memory.summary()
    assert summary["authoritative"] is False
    assert summary["execution_capability"] is False
