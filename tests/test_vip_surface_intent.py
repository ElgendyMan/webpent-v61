"""Regression contracts for passive application-intent and identity enrichment."""

from webpent.shared.surface_security import analyze_security_surface
from webpent.shared.workflow_understanding import (
    extract_workflow_observations,
    generate_business_logic_hypotheses,
)


def _identity_workflow_data() -> dict:
    return {
        "endpoints": ["https://lab.example/orders/approve?account_id=42"],
        "forms": [
            {
                "action": "/orders/approve",
                "method": "POST",
                "requires_auth": True,
                "actor_role": "reviewer",
                "authorization_scope": "orders:approve",
                "account_id": "account-42",
                "operation": "approve order",
                "workflow": "order-review",
            }
        ],
        "workflow_observations": [
            {"fingerprint": "workflow-fingerprint-123456789", "workflow": "order-review"}
        ],
    }


def test_surface_summary_enriches_intent_without_plaintext_identity() -> None:
    data = _identity_workflow_data()
    summary = analyze_security_surface(data, "https://lab.example")
    serialized = str(summary)

    assert "transactional" in summary["application_intent"]
    assert "privileged_administration" in summary["application_intent"]
    assert summary["identity_context_refs"]
    assert summary["workflow_refs"]
    assert "reviewer" not in serialized
    assert "account-42" not in serialized


def test_workflow_identity_context_is_opaque_and_hypothesis_is_gated() -> None:
    data = _identity_workflow_data()
    observations = extract_workflow_observations(data, target_url="https://lab.example")
    assert observations
    item = observations[0]
    assert item.authorization_boundary == "role_scoped"
    assert "identity_context" in item.signals
    assert item.identity_ref is None or item.identity_ref.startswith("identity:")
    assert "reviewer" not in item.model_dump_json()

    specs = generate_business_logic_hypotheses(observations, target_url="https://lab.example")
    identity_specs = [spec for spec in specs if "identity_boundary" in spec.origin_detail]
    assert identity_specs
    assert all(spec.action_type == "approval_required" for spec in identity_specs)
    assert all(spec.request_budget == 0 for spec in identity_specs)



def test_surface_and_intent_provenance_is_bounded_and_redacted() -> None:
    from webpent.shared.application_intent_graph import build_application_intent_model
    from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

    data = {
        "endpoints": [
            {
                "url": "https://lab.example/orders/approve?account_id=account-42&token=secret",
                "method": "POST",
                "source": "authenticated_crawler",
                "identity": "owner",
                "workflow_state": "review",
                "fields": {"account_id": "account-42"},
                "requires_auth": True,
                "authorization": "role_scoped",
            }
        ],
        "identity_matrix": [
            {
                "role": "owner",
                "source_kind": "credentialed_replay",
                "identity": "owner",
            }
        ],
    }

    surface = build_surface_evidence_graph(data, target_url="https://lab.example")
    intent = build_application_intent_model(data, target_url="https://lab.example")

    assert surface.nodes
    assert any("authenticated_crawler" in item.provenance for item in surface.nodes)
    assert all("secret" not in str(item.model_dump()).lower() for item in surface.nodes)
    intent_nodes = [
        *intent.actors,
        *intent.objects,
        *intent.fields,
        *intent.trust_boundaries,
        *intent.sinks,
        *intent.state_transitions,
        *intent.background_jobs,
        *intent.service_dependencies,
    ]
    assert intent_nodes
    assert any("authenticated_crawler" in item.provenance for item in intent_nodes)
    assert intent.identities
    assert any("credentialed_replay" in item.provenance for item in intent.identities)
    assert all("account-42" not in str(item.model_dump()).lower() for item in intent_nodes)
    assert all("secret" not in str(item.model_dump()).lower() for item in intent_nodes)



def test_string_only_surface_observation_is_explicitly_passive() -> None:
    from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

    graph = build_surface_evidence_graph(
        {"endpoints": ["https://lab.example/search?q=term"]},
        target_url="https://lab.example",
    )

    endpoint = next(node for node in graph.nodes if node.node_type == "endpoint")
    assert endpoint.provenance == ["passive_observation"]
    assert "term" not in str(endpoint.model_dump()).lower()
    assert "[redacted]" in endpoint.label.lower() or "?q=" not in endpoint.label



def test_intent_provenance_does_not_upgrade_confidence() -> None:
    from webpent.shared.application_intent_graph import build_application_intent_model

    model = build_application_intent_model(
        {
            "endpoints": [
                {
                    "url": "https://lab.example/orders/approve",
                    "source": "authenticated_crawler",
                    "identity": "owner",
                    "fields": {"order_id": "opaque"},
                    "operation": "approve_order",
                }
            ]
        },
        target_url="https://lab.example",
    )

    intent_nodes = [
        *model.actors,
        *model.objects,
        *model.fields,
        *model.trust_boundaries,
        *model.sinks,
        *model.state_transitions,
        *model.background_jobs,
        *model.service_dependencies,
    ]
    assert intent_nodes
    assert all(node.confidence < 1.0 for node in intent_nodes)
    assert all(node.provenance for node in intent_nodes)
