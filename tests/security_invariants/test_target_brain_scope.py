from __future__ import annotations

from webpent.agents.target_understanding.agent import target_understanding_node
from webpent.models.targets import Target


def test_target_brain_excludes_out_of_scope_forms_and_workflows() -> None:
    state = {
        "target": Target(url="http://lab.local", in_scope_regex=[r"lab\.local"]),
        "engagement_id": "engagement-scope-test",
        "crawled_data": {
            "endpoints": [
                "http://lab.local/profile",
                "http://outside.example/admin",
            ],
            "resources": [
                {
                    "type": "profile",
                    "object_id": "profile-1",
                    "url": "http://lab.local/profile",
                    "owner_identity": "user-1",
                }
            ],
            "forms": [
                {"action": "http://lab.local/profile", "method": "POST"},
                {"action": "http://outside.example/admin", "method": "POST"},
            ],
        },
        "identity_profiles": [
            {"name": "user-1", "role": "member"},
        ],
    }

    result = target_understanding_node(state)  # type: ignore[arg-type]

    workflows = result["target_knowledge"]["workflows"]
    workflow_names = {workflow["name"] for workflow in workflows.values()}
    assert "form:profile" in workflow_names
    assert "form:admin" not in workflow_names

    knowledge = result["target_knowledge"]
    profile_nodes = [
        node
        for node in knowledge.get("nodes", {}).values()
        if (
            node.get("kind") == "object"
            and node.get("metadata", {}).get("object_type") == "profile"
            and node.get("metadata", {}).get("url") == "http://lab.local/profile"
        )
    ]
    assert profile_nodes
    profile_node_id = profile_nodes[0]["node_id"]
    identity_nodes = [
        node
        for node in knowledge.get("nodes", {}).values()
        if node.get("kind") == "identity"
    ]
    assert identity_nodes
    identity_node_ids = {node["node_id"] for node in identity_nodes}
    assert any(
        edge.get("source_id") in identity_node_ids
        and edge.get("target_id") == profile_node_id
        and edge.get("relation") == "owns"
        for edge in knowledge.get("edges", [])
    )

    workflow = next(
        item for item in knowledge["workflows"].values() if item["name"] == "form:profile"
    )
    assert workflow.get("required_role") == "member"
    assert workflow["transitions"]
    transition = workflow["transitions"][0]
    assert {"method", "endpoint", "from_state", "to_state"}.issubset(transition)
    assert transition["endpoint"] == "http://lab.local/profile"

    assert any(
        edge.get("source_id") == "form:profile"
        and edge.get("relation") == "contains"
        for edge in knowledge.get("edges", [])
    )
    assert all(
        node["canonical_key"] != "http://outside.example/admin"
        for node in knowledge.get("nodes", {}).values()
    )
    assert all(
        workflow.get("name") != "form:admin"
        for workflow in knowledge.get("workflows", {}).values()
    )
