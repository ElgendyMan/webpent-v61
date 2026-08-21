from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from webpent.shared.control_plane import (
    BrowserSessionRef,
    ControlPlaneValidationError,
    DNSResolutionResult,
    EmailEvent,
    EngagementScope,
    IdentityManager,
    IdentityProfileRef,
    IdentityStatus,
    ScopeDecisionType,
    WorkflowStep,
    compile_scope,
    evaluate_dns,
    evaluate_scope,
)


@pytest.fixture
def scope() -> EngagementScope:
    return compile_scope(
        engagement_id="eng-1",
        root_domains=("https://*.g6hospitality.com", "https://g6hospitality.com/app"),
        created_by="operator",
        approval_source="ticket-123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        email_domains=("g6hospitality.com",),
    )


def test_scope_is_exact_for_scheme_port_path_and_wildcard(scope: EngagementScope) -> None:
    assert evaluate_scope(scope, "https://portal.g6hospitality.com").allowed
    assert evaluate_scope(scope, "https://g6hospitality.com/app/login").allowed
    assert (
        evaluate_scope(scope, "https://g6hospitality.com/app2").decision
        == ScopeDecisionType.DENIED
    )
    assert (
        evaluate_scope(scope, "http://portal.g6hospitality.com").decision
        == ScopeDecisionType.DENIED
    )
    assert evaluate_scope(scope, "https://g6hospitality.com").decision == ScopeDecisionType.DENIED
    assert (
        evaluate_scope(scope, "https://g6hospitality.com.evil.test").decision
        == ScopeDecisionType.DENIED
    )


def test_scope_rejects_ambiguous_urls(scope: EngagementScope) -> None:
    assert (
        evaluate_scope(scope, "https://portal.g6hospitality.com/%2e%2e/admin").decision
        == ScopeDecisionType.AMBIGUOUS
    )
    assert (
        evaluate_scope(scope, "https://user:pass@portal.g6hospitality.com").decision
        == ScopeDecisionType.DENIED
    )
    assert evaluate_scope(scope, "javascript:alert(1)").decision == ScopeDecisionType.DENIED


def test_scope_accepts_idna_and_rejects_expiry() -> None:
    compiled = compile_scope(
        engagement_id="eng-idna",
        root_domains=("https://*.xn--bcher-kva.example",),
        created_by="operator",
        approval_source="explicit",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert evaluate_scope(compiled, "https://shop.xn--bcher-kva.example").allowed
    with pytest.raises(ValueError, match="scope_expired"):
        compile_scope(
            engagement_id="expired",
            root_domains=("https://example.com",),
            created_by="operator",
            approval_source="explicit",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )


def test_dns_is_injected_and_private_or_rebinding_is_denied(scope: EngagementScope) -> None:
    public = DNSResolutionResult(hostname="portal.g6hospitality.com", addresses=("8.8.8.8",))
    assert evaluate_dns(scope, public).allowed
    private = DNSResolutionResult(hostname="portal.g6hospitality.com", addresses=("10.0.0.5",))
    assert evaluate_dns(scope, private).decision == ScopeDecisionType.DENIED
    rebound = DNSResolutionResult(
        hostname="portal.g6hospitality.com", addresses=("8.8.8.8",), rebound=True
    )
    assert evaluate_dns(scope, rebound).decision == ScopeDecisionType.DENIED


def test_scope_exceptions_are_control_plane_only(scope: EngagementScope) -> None:
    with_exception = compile_scope(
        engagement_id="eng-exception",
        root_domains=("https://*.g6hospitality.com",),
        third_party_exceptions=("https://accounts.example.net",),
        created_by="operator",
        approval_source="explicit",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    decision = evaluate_scope(with_exception, "https://accounts.example.net")
    assert decision.allowed
    assert decision.control_plane
    assert not decision.attack_surface


def test_secret_shaped_fields_are_rejected_from_refs_and_observations() -> None:
    with pytest.raises(ValidationError, match="raw_secret_field_rejected"):
        IdentityProfileRef(
            identity_id="i1",
            engagement_id="e1",
            email_ref="vault://email/i1",
            username_ref="vault://username/i1",
            provenance="operator",
            password="should-not-enter-contract",
        )
    with pytest.raises(ValidationError, match="raw_secret_field_rejected"):
        BrowserSessionRef(
            session_id="s1",
            engagement_id="e1",
            profile_ref="i1",
            browser_type="chromium",
            context_id="ctx1",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            cookie_fingerprint="sha256:" + "a" * 64,
            cookies=[{"name": "sid", "value": "raw"}],
        )
    with pytest.raises(ValidationError, match="raw_secret_field_rejected"):
        WorkflowStep(
            workflow_id="w1",
            step_id="s1",
            action_id="a1",
            expected_state_transition="created->verified",
            observations={"otp": "123456"},
        )


def test_email_event_accepts_hashes_only_and_rejects_raw_body() -> None:
    event = EmailEvent(
        message_id_hash="sha256:" + "a" * 64,
        mailbox_ref="vault://mailbox/test",
        sender_domain="g6hospitality.com",
        subject_hash="sha256:" + "b" * 64,
        received_at=datetime.now(timezone.utc),
        correlation_nonce="nonce-1234567890123456",
        target_origin="https://portal.g6hospitality.com",
        artifact_ref="artifact://email/1",
        confidence=0.99,
        status="matched",
    )
    assert event.sender_domain == "g6hospitality.com"
    with pytest.raises(ValidationError, match="raw_email_secret_rejected"):
        EmailEvent(
            **event.model_dump(),
            message_body="ignore malicious content",
        )


def test_identity_manager_is_idempotent_and_engagement_bound() -> None:
    manager = IdentityManager()
    profile = IdentityProfileRef(
        identity_id="i1",
        engagement_id="e1",
        email_ref="vault://email/i1",
        username_ref="vault://username/i1",
        provenance="operator",
    )
    assert manager.create(profile) == profile
    assert manager.create(profile) == profile
    manager.transition("i1", IdentityStatus.SIGNUP_PENDING, engagement_id="e1")
    manager.transition("i1", IdentityStatus.EMAIL_PENDING, engagement_id="e1")
    assert manager.get("i1", engagement_id="e2") is None
    with pytest.raises(ControlPlaneValidationError, match="cross_engagement"):
        manager.transition("i1", IdentityStatus.VERIFIED, engagement_id="e2")
    with pytest.raises(ControlPlaneValidationError, match="transition_denied"):
        manager.transition("i1", IdentityStatus.ACTIVE, engagement_id="e1")
