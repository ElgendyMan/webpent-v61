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
            "forms": [
                {"action": "http://lab.local/profile", "method": "POST"},
                {"action": "http://outside.example/admin", "method": "POST"},
            ],
        },
    }

    result = target_understanding_node(state)  # type: ignore[arg-type]

    workflows = result["target_knowledge"]["workflows"]
    workflow_names = {workflow["name"] for workflow in workflows.values()}
    assert "form:profile" in workflow_names
    assert "form:admin" not in workflow_names

    knowledge = result["target_knowledge"]
    assert all(
        node["canonical_key"] != "http://outside.example/admin"
        for node in knowledge.get("nodes", {}).values()
    )
    assert all(
        workflow.get("name") != "form:admin"
        for workflow in knowledge.get("workflows", {}).values()
    )
