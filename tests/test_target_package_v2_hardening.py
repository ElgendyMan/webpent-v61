from __future__ import annotations

import pytest
from bbscout.models import (
    CapabilityProfile,
    NormalizedRule,
    ProgramSummary,
    ScopeAssessment,
    ScoreBreakdown,
)
from bbscout.packages import build_target_package
from bbscout.signatures import sign_target_package, verify_detached_signature
from bbscout.target_package_v2 import validate_target_package
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webpent.models.findings import Finding
from webpent.models.targets import Target
from webpent.reporter.export import build_report_data
from webpent.shared.action_authority import ActionAuthority, ActionRequest
from webpent.shared.engagement_factory import EngagementAdmissionError, EngagementFactory
from webpent.shared.package_preflight import target_package_preflight_node
from webpent.shared.package_scope import ScopeCompiler, ScopeDecisionStatus
from webpent.shared.target_package_context import admit_target_package
from webpent.shared.verifier import verify_replay_evidence
from webpent.state.initial_state import build_initial_state


def make_package() -> dict:
    program = ProgramSummary(
        provider="hackerone",
        program_id="fixture-program-1",
        handle="fixture-program",
        name="Fixture Program",
        status="active",
        visibility="public",
        policy_text="Only test the explicitly listed fixture host.",
        source_url="https://example.test/policy",
    )
    scope = ScopeAssessment(
        status="ready",
        normalized_rules=[
            NormalizedRule(
                rule_id="include-root",
                action="include",
                asset_type="url",
                scheme="http",
                host="example.test",
                port=80,
                path="/app",
                wildcard=False,
                raw_value="http://example.test/app",
                decision_reason="explicit fixture include",
                source_asset_id="asset-1",
            ),
            NormalizedRule(
                rule_id="exclude-admin",
                action="exclude",
                asset_type="url",
                scheme="http",
                host="example.test",
                port=80,
                path="/app/admin",
                wildcard=False,
                raw_value="http://example.test/app/admin",
                decision_reason="explicit fixture exclusion",
                source_asset_id="asset-2",
            ),
        ],
        warnings=[],
        exclusion_count=1,
        include_count=1,
        assessed_at="2026-08-22T00:00:00Z",
    )
    score = ScoreBreakdown(
        score=0.95,
        confidence="high",
        uncertainty_low=0.9,
        uncertainty_high=1.0,
        eligibility="eligible",
        reasons=["fixture"],
        blockers=[],
        features={},
    )
    profile = CapabilityProfile(
        profile_version="fixture-v1",
        qualified_capabilities={"http_read": True},
        validators={"fixture": True},
        confirmation={"causal_signal": True, "negative_control": True},
    )
    return build_target_package(
        program=program,
        scope=scope,
        score=score,
        profile=profile,
        raw_sources={"adapter_version": "fixture-adapter-v1", "source_kind": "offline"},
        confirmed_by_user=True,
    )


def signed_package() -> tuple[dict, Ed25519PrivateKey]:
    package = make_package()
    private_key = Ed25519PrivateKey.generate()
    return (
        sign_target_package(
            package,
            private_key=private_key,
            key_id="fixture-runtime-key",
        ),
        private_key,
    )


def test_real_bbscout_package_admits_into_initial_state_without_source_hash_confusion(tmp_path):
    package = make_package()
    context = admit_target_package(package)
    assert context.package_sha256 == package["integrity"]["content_sha256"]
    assert context.source_sha256 == package["source"]["source_response_sha256"]
    assert context.package_sha256 != context.source_sha256

    state = build_initial_state(
        Target(url="http://example.test/app"),
        engagement_id="fixture-engagement",
        action_ledger_path=str(tmp_path / "actions.sqlite3"),
        target_package=package,
    )
    assert state["target_package_status"] == "ready"
    assert state["target_package_id"] == package["package_id"]
    assert state["target_package_sha256"] == package["integrity"]["content_sha256"]


def test_detached_signature_is_real_and_unsigned_is_not_executable():
    package, private_key = signed_package()
    public_key = private_key.public_key()
    result = validate_target_package(
        package,
        require_detached_signature=True,
        trusted_public_keys={"fixture-runtime-key": public_key},
    )
    assert result.valid is True
    assert result.signature_state == "verified"
    verify_detached_signature(
        package,
        trusted_public_keys={"fixture-runtime-key": public_key},
    )
    unsigned = make_package()
    rejected = validate_target_package(
        unsigned,
        require_detached_signature=True,
        trusted_public_keys={"fixture-runtime-key": public_key},
    )
    assert rejected.valid is False
    assert "detached_signature_not_verified" in rejected.errors


def test_engagement_factory_consumes_signed_package_once(tmp_path):
    package, private_key = signed_package()
    factory = EngagementFactory(
        tmp_path / "leases.sqlite3",
        signature_verifier=lambda value: verify_detached_signature(
            value,
            trusted_public_keys={"fixture-runtime-key": private_key.public_key()},
        ),
    )
    confirmation = {
        "user_confirmed": True,
        "package_id": package["package_id"],
        "package_sha256": package["integrity"]["content_sha256"],
        "engagement_id": "engagement-once",
        "target_url": "http://example.test/app",
    }
    binding = factory.create_from_package(package, confirmation)
    assert binding.package_id == package["package_id"]
    assert binding.as_dict()["target_package_status"] == "consumed"
    with pytest.raises(EngagementAdmissionError, match="package_already_consumed"):
        factory.create_from_package(package, {**confirmation, "engagement_id": "engagement-again"})


def test_scope_compiler_handles_path_exclusion_apex_sibling_and_userinfo():
    compiler = ScopeCompiler.from_package_context(admit_target_package(make_package()))
    assert compiler.decide("http://example.test/app/x").status is ScopeDecisionStatus.ALLOW
    assert (
        compiler.decide("http://example.test/app/admin").status
        is ScopeDecisionStatus.DENY_OUT_OF_SCOPE
    )
    assert (
        compiler.decide("http://example.test/app2").status
        is ScopeDecisionStatus.DENY_OUT_OF_SCOPE
    )
    assert (
        compiler.decide("http://sibling.example.test/app").status
        is ScopeDecisionStatus.DENY_OUT_OF_SCOPE
    )
    assert (
        compiler.decide("http://example.test/app", method="POST").status
        is ScopeDecisionStatus.ALLOW
    )
    assert (
        compiler.decide("http://user:pass@example.test/app").status
        is ScopeDecisionStatus.DENY_AMBIGUOUS
    )


def test_package_preflight_emits_capability_gap_without_cleaning_it():
    package, _ = signed_package()
    projection = admit_target_package(package).as_state()
    result = target_package_preflight_node(
        {
            "target": {"url": "http://example.test/app"},
            "target_package": projection,
            "target_package_status": "ready",
            "capability_manifest": {
                "capabilities": {"http_read": {"available": True}}
            },
        }
    )
    assert result["target_package_preflight_status"] == "partial"
    assert result["target_package_knowledge_gaps"]
    assert result["target_package_blocked_tasks"]
    assert all(
        gap["status"] == "unavailable"
        for gap in result["target_package_knowledge_gaps"]
    )


def test_package_preflight_blocks_target_outside_compiled_scope():
    package, _ = signed_package()
    projection = admit_target_package(package).as_state()
    result = target_package_preflight_node(
        {
            "target": {"url": "http://sibling.example.test/app"},
            "target_package": projection,
            "target_package_status": "ready",
            "capability_manifest": {},
        }
    )
    assert result["target_package_preflight_status"] == "blocked"
    assert result["target_package_blocked_tasks"][0]["task"] == "engagement"
    assert result["target_package_knowledge_gaps"][0]["status"] == "deny_out_of_scope"


def test_package_preflight_blocks_unsigned_package_before_planning():
    projection = admit_target_package(make_package()).as_state()
    result = target_package_preflight_node(
        {
            "target": {"url": "http://example.test/app"},
            "target_package": projection,
            "target_package_status": "ready",
            "capability_manifest": {},
        }
    )
    assert result["target_package_preflight_status"] == "blocked"
    assert result["target_package_knowledge_gaps"][0]["unknown"] == (
        "detached_signature_not_verified"
    )


def test_action_authority_uses_package_scope_instead_of_exact_origin():
    projection = admit_target_package(make_package()).as_state()
    authority = ActionAuthority(
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        target_package=projection,
        scope_compiler=ScopeCompiler.from_projection(projection),
    )
    request = ActionRequest(
        task_id="task-1",
        engagement_id="engagement-1",
        target_url="http://example.test/app/x",
        idempotency_key="fixture-action-1",
        metadata={
            "target_package_id": projection["package_id"],
            "target_package_sha256": projection["package_sha256"],
        },
    )
    decision = authority.authorize(request)
    assert decision.allowed is True
    denied = authority.authorize(
        ActionRequest(
            task_id="task-2",
            engagement_id="engagement-1",
            target_url="http://example.test/app/admin",
            idempotency_key="fixture-action-2",
            metadata={
                "target_package_id": projection["package_id"],
                "target_package_sha256": projection["package_sha256"],
            },
        )
    )
    assert denied.allowed is False
    assert any(reason.startswith("scope:deny_out_of_scope") for reason in denied.reasons)


def test_package_continuity_survives_action_verifier_proof_and_report_hash():
    package, private_key = signed_package()
    projection = admit_target_package(package).as_state()
    authority = ActionAuthority(
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        target_package=projection,
        scope_compiler=ScopeCompiler.from_projection(projection),
    )
    action = ActionRequest(
        task_id="task-e2e",
        engagement_id="engagement-e2e",
        target_url="http://example.test/app/x",
        idempotency_key="fixture-action-e2e",
        metadata={
            "target_package_id": projection["package_id"],
            "target_package_sha256": projection["package_sha256"],
        },
    )
    decision = authority.authorize(action)
    assert decision.allowed is True

    finding = Finding(
        title="Cross-user object access",
        severity="high",
        description="A foreign identity accessed an object owned by another identity.",
        tool_name="offline-fixture",
        url="http://example.test/app/x",
        vuln_class="idor",
    )
    verification = verify_replay_evidence(
        finding,
        baseline={"status_code": 403, "identity": "anonymous"},
        candidate={"status_code": 200, "identity": "foreign"},
        negative_control={"status_code": 403, "identity": "anonymous"},
        causal_signal=True,
        negative_control_complete=True,
        validator_id="fixture.idor",
        validator_version="fixture.v1",
        causal_basis=(
            "foreign identity received the protected object while anonymous control "
            "was denied"
        ),
        engagement_id=action.engagement_id,
        hypothesis_id="hyp-e2e",
        scope_context={"target_origin": "http://example.test", "scope_bound": True},
        identity_context={
            "owner": "owner",
            "candidate": "foreign",
            "negative_control": "anonymous",
        },
        replay_metadata={"action_id": "fixture-action-e2e", "method": "GET"},
        target_package_id=action.metadata["target_package_id"],
        target_package_sha256=action.metadata["target_package_sha256"],
        target_package_scope_digest=projection["scope_digest"],
        target_package_policy_digest=projection["policy_digest"],
    )
    assert verification.passed is True
    assert verification.proof_bundle is not None
    proof = verification.proof_bundle.model_dump(mode="json")
    assert proof["target_package_id"] == projection["package_id"]
    assert proof["target_package_sha256"] == projection["package_sha256"]

    report_finding = finding.model_dump(mode="json")
    report_finding.update(
        {
            "confidence": "confirmed",
            "confidence_level": "Tool-Confirmed",
            "evidence_bundle": verification.evidence,
            "proof_bundle": proof,
        }
    )
    report = build_report_data(
        target_url="http://example.test/app",
        findings=[report_finding],
        target_package=projection,
    )
    continuity = report["target_package_continuity"]
    assert continuity["package_id"] == projection["package_id"]
    assert continuity["package_sha256"] == projection["package_sha256"]
    assert continuity["signature_state"] == "verified"
    assert continuity["status"] == "ready"
    assert report["audit_trail"]["master_report_hash"]
    assert projection["package_id"] in report["audit_trail"]["master_report_hash"] or isinstance(
        report["audit_trail"]["master_report_hash"], str
    )
