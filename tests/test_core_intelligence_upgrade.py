from datetime import UTC, datetime

from webpent.attack_graph import AttackGraphEngine
from webpent.knowledge.model_v2 import build_target_knowledge_v2
from webpent.models.findings import VulnClass
from webpent.research import HypothesisGenerator, ResearchPlanner

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def _entity(kind: str, key: str, confidence: float = 0.9) -> dict:
    return {
        "kind": kind,
        "canonical_key": key,
        "source_observation": "obs:upgrade",
        "confidence": confidence,
        "evidence_refs": ["evidence:upgrade"],
    }


def _expanded_model():
    observation = {
        "observation_id": "obs:upgrade",
        "source": "recorded-fixture",
        "observed_at": NOW,
        "confidence": 1.0,
        "evidence_refs": ["evidence:upgrade"],
    }
    entities = [
        _entity("identity", "identity:opaque", 1.0),
        _entity("endpoint", "GET /objects/{id}", 0.95),
        _entity("resource", "resource:opaque"),
        _entity("role", "role:opaque"),
        _entity("permission", "permission:opaque"),
        _entity("trust_boundary", "tenant:opaque"),
        _entity("workflow", "workflow:opaque"),
        _entity("parameter", "parameter:opaque"),
        _entity("data_flow", "data-flow:opaque"),
    ]
    base = build_target_knowledge_v2(
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
        observations=[observation],
        entities=entities,
    )
    ids = {entity.canonical_key: entity.entity_id for entity in base.entities.values()}
    relation_pairs = [
        ("exposes", "identity:opaque", "GET /objects/{id}"),
        ("can_access", "GET /objects/{id}", "resource:opaque"),
        ("requires_role", "GET /objects/{id}", "role:opaque"),
        ("grants", "role:opaque", "permission:opaque"),
        ("can_access", "GET /objects/{id}", "permission:opaque"),
        ("belongs_to", "resource:opaque", "tenant:opaque"),
        ("scoped_by", "GET /objects/{id}", "tenant:opaque"),
        ("transitions", "GET /objects/{id}", "workflow:opaque"),
        ("requires", "workflow:opaque", "GET /objects/{id}"),
        ("can_modify", "GET /objects/{id}", "workflow:opaque"),
        ("accepts", "GET /objects/{id}", "parameter:opaque"),
        ("has_parameter", "parameter:opaque", "GET /objects/{id}"),
        ("contains_parameter", "GET /objects/{id}", "parameter:opaque"),
        ("reflects", "GET /objects/{id}", "parameter:opaque"),
        ("queries", "GET /objects/{id}", "parameter:opaque"),
        ("fetches", "GET /objects/{id}", "data-flow:opaque"),
        ("resolves", "data-flow:opaque", "GET /objects/{id}"),
        ("flows_to", "GET /objects/{id}", "data-flow:opaque"),
        ("references", "GET /objects/{id}", "parameter:opaque"),
        ("reads", "parameter:opaque", "GET /objects/{id}"),
    ]
    relations = [
        {
            "relation": relation,
            "source_entity": ids[source],
            "target_entity": ids[target],
            "source_observation": "obs:upgrade",
            "confidence": 0.9,
            "evidence_refs": ["evidence:upgrade"],
        }
        for relation, source, target in relation_pairs
    ]
    return build_target_knowledge_v2(
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
        observations=[observation],
        entities=entities,
        relations=relations,
    )


def test_expanded_patterns_cover_multiple_generic_surfaces_without_execution_material():
    model = _expanded_model()
    graph = AttackGraphEngine().build(model)
    hypotheses = HypothesisGenerator(max_hypotheses=128).generate(model, graph)
    reasons = {item.reason for item in hypotheses}
    expected_patterns = {
        "object_authorization_boundary",
        "privilege_escalation_boundary",
        "tenant_isolation_boundary",
        "workflow_authorization_boundary",
        "parameter_reflection_surface",
        "query_interpretation_surface",
        "server_side_fetch_boundary",
        "path_resolution_boundary",
    }
    assert all(any(pattern in reason for reason in reasons) for pattern in expected_patterns)
    assert {item.vuln_class for item in hypotheses} >= {
        VulnClass.IDOR,
        VulnClass.AUTH_BYPASS,
        VulnClass.XSS,
        VulnClass.SQLI,
        VulnClass.SSRF,
        VulnClass.PATH_TRAVERSAL,
    }
    for item in hypotheses:
        serialized = item.model_dump(mode="json")
        assert all("payload" not in key.lower() for key in serialized)
        assert all("request_body" not in key.lower() for key in serialized)


def test_planner_supports_portfolio_novelty_and_attempted_hypothesis_filtering():
    model = _expanded_model()
    graph = AttackGraphEngine().build(model)
    hypotheses = HypothesisGenerator(max_hypotheses=128).generate(model, graph)
    planner = ResearchPlanner(max_tasks=3)
    attempted = hypotheses[0]
    attempted_task_id = planner.task_id(
        attempted,
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
    )
    queue = planner.build_queue(
        hypotheses,
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
        available_capabilities={"http_read"},
        attempted_hypothesis_ids={str(attempted.id)},
    )
    assert len(queue.tasks) <= 3
    assert queue.tasks
    assert all(task.operation == "validate" for task in queue.tasks)
    assert attempted_task_id not in {task.task_id for task in queue.tasks}
    assert queue.tasks == queue.ordered()


def test_unified_core_composes_discovery_planning_and_decision_without_authority():
    from webpent.vabhfqr_v9 import VABHFQRV9Core

    model = _expanded_model()
    graph = AttackGraphEngine().build(model)
    snapshot = VABHFQRV9Core().build_unified_intelligence(
        knowledge=model,
        graph=graph,
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
        scope_verified=True,
        remaining_budget=2,
        max_steps=2,
    )
    assert len(snapshot.hypothesis_ids) >= 8
    assert snapshot.queue_task_ids
    assert snapshot.selected_task_id in snapshot.queue_task_ids
    assert snapshot.decision_status == "continue"
    assert snapshot.confirmation_posture == "not_evaluated"
    assert snapshot.requests_sent == 0
    assert not snapshot.execution_allowed
    assert not snapshot.mutation_allowed
    assert not snapshot.finding_created
    assert not snapshot.qualification_effect
    assert snapshot.digest()


def test_unified_core_replans_for_missing_evidence_before_selecting_more_work():
    from webpent.vabhfqr_v9 import VABHFQRV9Core

    model = _expanded_model()
    graph = AttackGraphEngine().build(model)
    snapshot = VABHFQRV9Core().build_unified_intelligence(
        knowledge=model,
        graph=graph,
        engagement_id="eng:upgrade",
        target_id="target:upgrade",
        scope_verified=True,
        remaining_budget=2,
        available_evidence=("observation:recorded",),
        required_evidence=("proof:sealed",),
    )
    assert snapshot.decision_status == "replan"
    assert snapshot.decision_stage == "evidence"
    assert "proof:sealed" in snapshot.recommendations
    assert snapshot.selected_task_id is None
    assert snapshot.requests_sent == 0
    assert not snapshot.scoring_eligible
    assert not snapshot.qualification_effect


def test_unified_core_fails_closed_for_untyped_recorded_inputs():
    from webpent.vabhfqr_v9 import VABHFQRV9Core

    snapshot = VABHFQRV9Core().build_unified_intelligence(
        knowledge={},  # type: ignore[arg-type]
        graph={},  # type: ignore[arg-type]
        engagement_id="eng:invalid",
        target_id="target:invalid",
        scope_verified=True,
        remaining_budget=2,
    )
    assert snapshot.decision_status == "blocked"
    assert snapshot.decision_stage == "discovery"
    assert snapshot.recommendations == ("typed_recorded_knowledge_and_graph_required",)
    assert snapshot.requests_sent == 0
    assert not snapshot.execution_allowed
    assert not snapshot.mutation_allowed
    assert not snapshot.finding_created
    assert not snapshot.qualification_effect
