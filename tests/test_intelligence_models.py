from __future__ import annotations

import pytest

from webpent.intelligence.application_model import ApplicationAsset, ApplicationModel
from webpent.intelligence.entity_graph import EntityGraph, EntityNode, EntityRelation
from webpent.intelligence.permission_graph import PermissionGraph, PermissionObservation
from webpent.intelligence.state_model import StateModel, StateSnapshot, StateTransition
from webpent.intelligence.workflow_graph import WorkflowGraph, WorkflowStep, WorkflowTransition


def test_application_model_merges_assets_without_cross_target_data() -> None:
    model = ApplicationModel(engagement_id="eng-1", target_id="target-1")
    model.add_asset(
        ApplicationAsset(
            asset_id="obj-1",
            kind="object",
            name="Invoice",
            evidence_refs=["obs-a"],
            confidence=0.4,
        )
    )
    model.add_asset(
        ApplicationAsset(
            asset_id="obj-1",
            kind="object",
            name="Invoice",
            evidence_refs=["obs-a", "obs-b"],
            confidence=0.8,
        )
    )
    assert model.assets["obj-1"].confidence == 0.8
    assert model.evidence_refs() == ["obs-a", "obs-b"]
    with pytest.raises(ValueError, match="asset_identity_conflict"):
        model.add_asset(
            ApplicationAsset(asset_id="obj-1", kind="payment", name="Invoice")
        )


def test_entity_graph_rejects_unknown_relation_endpoints() -> None:
    graph = EntityGraph(engagement_id="eng-1", target_id="target-1")
    graph.add_node(EntityNode(node_id="user-1", entity_type="user", label="User"))
    with pytest.raises(ValueError, match="entity_relation_requires_known_nodes"):
        graph.add_relation(
            EntityRelation(
                source_id="user-1",
                relation="owns",
                target_id="invoice-1",
            )
        )


def test_workflow_graph_and_state_model_require_known_nodes() -> None:
    workflow = WorkflowGraph(engagement_id="eng-1", target_id="target-1")
    workflow.add_step(WorkflowStep(step_id="start", label="Start"))
    workflow.add_step(WorkflowStep(step_id="finish", label="Finish"))
    workflow.add_transition(
        WorkflowTransition(
            source_step_id="start",
            target_step_id="finish",
            transition="submit",
            evidence_refs=["workflow-1"],
        )
    )
    assert workflow.entry_steps() == ["start"]

    state = StateModel(engagement_id="eng-1", target_id="target-1")
    state.add_state(StateSnapshot(state_id="draft", label="Draft"))
    state.add_state(StateSnapshot(state_id="paid", label="Paid"))
    state.add_transition(
        StateTransition(
            source_state_id="draft",
            target_state_id="paid",
            operation="pay",
            observed=True,
            invariant_refs=["owner_required"],
        )
    )
    assert state.candidate_invariants() == ["owner_required"]


def test_permission_graph_is_observation_only_and_stable() -> None:
    graph = PermissionGraph(engagement_id="eng-1", target_id="target-1")
    graph.add_observation(
        PermissionObservation(
            principal_id="user-1",
            resource_id="invoice-1",
            action="read",
            access="allow",
            evidence_refs=["perm-1"],
        )
    )
    graph.add_observation(
        PermissionObservation(
            principal_id="user-2",
            resource_id="invoice-1",
            action="read",
            access="deny",
            evidence_refs=["perm-2"],
        )
    )
    assert graph.matrix() == {
        "user-1:invoice-1": {"read": "allow"},
        "user-2:invoice-1": {"read": "deny"},
    }
    assert graph.evidence_refs() == ["perm-1", "perm-2"]
