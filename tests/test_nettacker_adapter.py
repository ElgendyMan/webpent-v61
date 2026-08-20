from __future__ import annotations

import ast
from pathlib import Path

from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import ActionAuthority, ActionRequest, ActionRisk
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.capability_manifest import build_capability_manifest
from webpent.shared.nettacker_adapter import (
    NETTACKER_COMMIT,
    adapt_nettacker_records,
    ingest_nettacker_records,
    nettacker_adapter_manifest,
    surface_data_from_nettacker,
)


def test_nettacker_events_are_normalized_as_observations_only() -> None:
    result = adapt_nettacker_records(
        "http://example.test",
        {
            "events": [
                {
                    "target": "example.test",
                    "module_name": "http_status",
                    "port": 443,
                    "event": "Detected",
                    "json_event": {"status_code": 200},
                }
            ]
        },
        scope_decision="allowed",
        endpoint="/",
        method="GET",
    )

    assert result.execution.status == "success"
    assert result.execution.tool_version.endswith(NETTACKER_COMMIT)
    assert len(result.observations) == 1
    value = result.observations[0].value
    assert value["module_name"] == "http_status"
    assert value["json_event"] == {"present": True, "field_count": 1}
    assert value["evidence_role"] == "recon_observation_only"
    assert value["source_commit"] == NETTACKER_COMMIT


def test_nettacker_cve_matches_are_enrichment_only() -> None:
    result = adapt_nettacker_records(
        "https://example.test",
        {"results": [{"module_name": "apache_cve_2021_41773", "cve": "CVE-2021-41773"}]},
        scope_decision="allowed",
    )

    assert result.execution.status == "success"
    value = result.observations[0].value
    assert value["evidence_role"] == "cve_enrichment_only"
    assert "finding" not in value
    assert "confirmation" not in value


def test_unsafe_fields_are_omitted_and_redacted() -> None:
    result = adapt_nettacker_records(
        "http://example.test",
        {
            "records": [
                {
                    "target": "example.test",
                    "module_name": "http_cookie",
                    "command": "curl --cookie secret",
                    "payload": "exploit-payload",
                    "authorization": "Bearer secret-token",
                    "port": 443,
                }
            ]
        },
    )

    value = result.observations[0].value
    assert "command" not in value
    assert "payload" not in value
    assert value["unsafe_fields_omitted"] == ["authorization", "command", "payload"]
    assert "secret-token" not in result.model_dump_json()
    assert "exploit-payload" not in result.model_dump_json()


def test_partial_envelope_is_not_reported_as_success() -> None:
    result = adapt_nettacker_records(
        "http://example.test",
        {"status": "timeout", "events": [{"target": "example.test", "port": 80}]},
    )

    assert result.execution.status == "partial"
    assert result.observations[0].status == "partial"


def test_malformed_input_is_failed_not_clean() -> None:
    result = adapt_nettacker_records(
        "http://example.test",
        {"events": ["not-an-object"]},
    )

    assert result.execution.status == "failed"
    assert result.error == "nettacker_event_object_required"
    assert not result.observations


def test_input_size_limit_is_bounded() -> None:
    result = adapt_nettacker_records(
        "http://example.test",
        {"description": "x" * (512 * 1024)},
    )

    assert result.execution.status == "failed"
    assert result.error == "nettacker_input_limit_exceeded"


def test_manifest_and_capability_are_import_only() -> None:
    adapter_manifest = nettacker_adapter_manifest()
    assert adapter_manifest["available"] is True
    assert adapter_manifest["execution_available"] is False
    assert adapter_manifest["network_io"] is False
    assert adapter_manifest["subprocess_io"] is False
    assert adapter_manifest["destructive"] is False
    assert adapter_manifest["fail_closed"] is True
    assert adapter_manifest["timeout_seconds"] == 0

    manifest = build_capability_manifest()
    capability = manifest["capabilities"]["nettacker_observation"]
    assert capability["available"] is True
    assert capability["execution_available"] is False
    assert manifest["fail_closed"] is True


def test_import_binding_uses_authority_and_ledger_without_external_execution(tmp_path) -> None:
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite")
    settings = Settings(scan_mode=ScanMode.SAFE_SMART, smart_require_idempotency=True)
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="http://example.test",
        manifest={"capabilities": {"nettacker_observation": {"available": True}}},
        ledger=ledger,
    )
    request = ActionRequest(
        task_id="task-local-nettacker",
        engagement_id="eng-local-nettacker",
        target_url="http://example.test",
        action_family="recon",
        capability="nettacker_observation",
        risk=ActionRisk.READ_ONLY,
        idempotency_key="nettacker-import-001",
        metadata={"tenant_context": "local", "vulnerability_class": "recon"},
    )

    result = ingest_nettacker_records(
        authority,
        request,
        {"events": [{"module_name": "http_status", "port": 80}]},
    )

    assert result.status.value == "executed"
    assert result.output.execution.parameters["action_id"] == request.idempotency_key
    assert result.output.observations[0].parameters["engagement_id"] == request.engagement_id
    assert ledger.snapshot(request.engagement_id)["used_actions"] == 1

    duplicate = ingest_nettacker_records(
        authority,
        request,
        {"events": [{"module_name": "http_status", "port": 80}]},
    )
    assert duplicate.status.value == "policy_denied"
    assert "duplicate_reservation" in duplicate.decision.reasons[0]


def test_nettacker_surfaces_reach_surface_graph_as_needs_validator() -> None:
    from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

    result = adapt_nettacker_records(
        "http://example.test",
        {
            "events": [
                {
                    "url": "http://example.test/admin",
                    "method": "POST",
                    "module_name": "http_status",
                },
                {"url": "http://other.test/outside", "method": "GET"},
                {"service": "https", "port": 443, "product": "nginx"},
            ]
        },
        scope_decision="allowed",
    )
    enriched = surface_data_from_nettacker({}, result, target_url="http://example.test")
    graph = build_surface_evidence_graph(enriched, target_url="http://example.test")

    labels = {node.label for node in graph.nodes}
    assert any("/admin" in label for label in labels)
    assert not any("other.test" in label for label in labels)
    assert graph.family_counts.get("api_or_form", 0) >= 1
    assert all(node.disposition == "needs_validator" for node in graph.nodes)
    assert enriched["nettacker_observation_count"] == 3


def test_adapter_has_no_direct_io_imports_or_shell_calls() -> None:
    source_path = Path(__file__).parents[1] / "src/webpent/shared/nettacker_adapter.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_imports = {"subprocess", "requests", "httpx", "socket", "urllib.request"}
    forbidden_calls = {"system", "popen", "Popen", "check_call", "check_output"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name not in forbidden_imports for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden_imports
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_calls
