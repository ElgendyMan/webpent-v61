from __future__ import annotations

import json

from webpent.shared.attack_graph import build_attack_graph


def _knowledge(engagement_id: str) -> dict[str, object]:
    return {
        "engagement_id": engagement_id,
        "nodes": {
            "identity-1": {
                "kind": "identity",
                "canonical_key": "buyer",
                "confidence": 0.9,
                "evidence_refs": ["obs:identity"],
                "metadata": {"role": "user", "token": "must-not-persist"},
            },
            "resource-1": {
                "kind": "object",
                "canonical_key": "invoice",
                "confidence": 0.8,
                "evidence_refs": ["obs:invoice"],
                "metadata": {},
            },
        },
        "edges": [
            {
                "source_id": "identity-1",
                "target_id": "resource-1",
                "relation": "creates",
                "confidence": 0.8,
                "evidence_refs": ["obs:relation"],
            }
        ],
        "authorization_profiles": {
            "buyer": {
                "identity_id": "identity-1",
                "observed_capabilities": ["invoice.read"],
                "authorization_status": "observed",
                "evidence_refs": ["obs:auth"],
            }
        },
        "data_flows": [
            {
                "source_id": "identity-1",
                "destination_id": "resource-1",
                "channel": "observed_api",
                "observed": True,
                "evidence_refs": ["obs:flow"],
            }
        ],
    }


def test_attack_graph_projects_target_knowledge_without_raw_metadata() -> None:
    graph = build_attack_graph({"nodes": {}, "edges": []}, target_knowledge=_knowledge("eng-a"))
    serialized = json.dumps(graph, sort_keys=True)

    assert "target_knowledge" in graph["generated_from"]
    assert any(node["kind"] == "identity" for node in graph["nodes"].values())
    assert any(node["kind"] == "resource" for node in graph["nodes"].values())
    assert any(node["kind"] == "permission" for node in graph["nodes"].values())
    assert any(edge["kind"] == "knowledge_creates" for edge in graph["edges"])
    assert any(edge["kind"] == "identity_has_permission" for edge in graph["edges"])
    assert any(edge["kind"] == "observed_data_flow" for edge in graph["edges"])
    assert "must-not-persist" not in serialized


def test_attack_graph_target_knowledge_scope_is_deterministic_and_isolated() -> None:
    first = build_attack_graph({"nodes": {}, "edges": []}, target_knowledge=_knowledge("eng-a"))
    second = build_attack_graph({"nodes": {}, "edges": []}, target_knowledge=_knowledge("eng-a"))
    other = build_attack_graph({"nodes": {}, "edges": []}, target_knowledge=_knowledge("eng-b"))

    assert first == second
    first_ids = set(first["nodes"])
    other_ids = set(other["nodes"])
    assert first_ids.isdisjoint(other_ids)


def test_attack_graph_preserves_typed_knowledge_and_runtime_gaps() -> None:
    graph = build_attack_graph(
        {"nodes": {}, "edges": []},
        knowledge_gaps=[
            {
                "gap_id": "gap:auth-1",
                "kind": "authorization",
                "status": "open",
                "target_ref": "http://example.test/api/item/1",
                "unknown": "owner binding",
                "candidate_actions": [{"action_class": "baseline"}],
                "unexpected_secret": "must-not-persist",
            }
        ],
        runtime_capability_gaps=[
            {
                "code": "browser_unavailable",
                "component": "browser",
                "required_for": "workflow_replay",
                "recovery_action": "install browser",
            }
        ],
    )

    assert graph["knowledge_gaps"] == [
        {
            "gap_id": "gap:auth-1",
            "kind": "authorization",
            "status": "open",
            "target_ref": "http://example.test/api/item/1",
            "unknown": "owner binding",
        }
    ]
    assert graph["runtime_capability_gaps"] == [
        {
            "code": "browser_unavailable",
            "component": "browser",
            "required_for": "workflow_replay",
            "recovery_action": "install browser",
        }
    ]
    assert "must-not-persist" not in str(graph)
    assert "candidate_actions" not in str(graph)

