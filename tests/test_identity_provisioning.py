from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from webpent.shared.control_plane import EngagementScope, compile_scope
from webpent.shared.identity_provisioning import (
    EmailVerificationWatcher,
    IdentityProvisioningAgent,
    IdentityProvisioningStatus,
    SignupFormDetected,
    SignupSubmitted,
    VerificationMaterialFound,
    identity_provisioning_node,
)


def _scope() -> EngagementScope:
    return compile_scope(
        engagement_id="eng-identity",
        root_domains=["https://app.example.test:443/"],
        created_by="local-test",
        approval_source="fixture",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        allowed_schemes=["https"],
        allowed_ports=[443],
        path_rules=["/"],
    )


def _event(url: str = "https://app.example.test/signup") -> SignupFormDetected:
    return SignupFormDetected(
        engagement_id="eng-identity",
        client_id="client-a",
        target_signup_url=url,
        detected_form_fields=("email", "password"),
    )


def test_provisioning_verifies_with_redacted_report_only() -> None:
    calls: list[tuple[str, str]] = []

    def submit(request: object, email: str, password: str) -> bool:
        calls.append((email, password))
        assert "password" not in request.__dict__
        return True

    def poll(submitted: SignupSubmitted) -> VerificationMaterialFound:
        return VerificationMaterialFound(
            correlation_id=submitted.correlation_id,
            target_origin="https://app.example.test/verify",
            material_type="link",
            material_ref="vault://eng-identity/mail/event-1",
            event_ref="mail-event-1",
        )

    agent = IdentityProvisioningAgent(
        submit_signup=submit,
        watcher=EmailVerificationWatcher(poll),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
    )
    result = agent.provision(_event(), _scope())

    assert result["status"] == IdentityProvisioningStatus.VERIFIED.value
    assert calls and calls[0][1] not in str(result)
    assert "OTP" not in str(result).upper()
    assert result["identity_records"]
    assert result["signup_submissions"]


def test_mailbox_timeout_is_inconclusive_not_confirmed() -> None:
    agent = IdentityProvisioningAgent(
        submit_signup=lambda _request, _email, _password: True,
        watcher=EmailVerificationWatcher(lambda _submitted: None),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
    )

    result = agent.provision(_event(), _scope())

    assert result["status"] == IdentityProvisioningStatus.INCONCLUSIVE.value
    assert "identity_records" not in result


def test_wrong_correlation_is_fail_closed() -> None:
    def poll(_submitted: SignupSubmitted) -> VerificationMaterialFound:
        return VerificationMaterialFound(
            correlation_id="corr-wrong-000000000000",
            target_origin="https://app.example.test/verify",
            material_type="otp",
            material_ref="vault://eng-identity/mail/event-2",
            event_ref="mail-event-2",
        )

    agent = IdentityProvisioningAgent(
        submit_signup=lambda _request, _email, _password: True,
        watcher=EmailVerificationWatcher(poll),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
    )

    result = agent.provision(_event(), _scope())

    assert result["status"] == IdentityProvisioningStatus.INCONCLUSIVE.value
    assert "identity_records" not in result


def test_out_of_scope_signup_is_blocked_before_submission() -> None:
    submitted = False

    def submit(_request: object, _email: str, _password: str) -> bool:
        nonlocal submitted
        submitted = True
        return True

    agent = IdentityProvisioningAgent(
        submit_signup=submit,
        watcher=EmailVerificationWatcher(lambda _submitted: None),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
    )

    result = agent.provision(_event("https://evil.example.test/signup"), _scope())

    assert result == {
        "status": IdentityProvisioningStatus.BLOCKED.value,
        "reason": "signup_url_out_of_scope",
    }
    assert submitted is False


def test_budget_is_bounded_per_engagement() -> None:
    agent = IdentityProvisioningAgent(
        submit_signup=lambda _request, _email, _password: True,
        watcher=EmailVerificationWatcher(lambda _submitted: None),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
        max_signups=1,
    )

    first = agent.provision(_event(), _scope())
    second = agent.provision(_event(), _scope())

    assert first["status"] == IdentityProvisioningStatus.INCONCLUSIVE.value
    assert second["status"] == IdentityProvisioningStatus.BLOCKED.value
    assert second["reason"] == "signup_budget_exhausted"


def test_identity_node_is_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.identity_provisioning.get_settings",
        lambda: SimpleNamespace(identity_provisioning_enabled=False),
    )
    assert identity_provisioning_node({"signup_forms_detected": [{"password": "x"}]}) == {
        "identity_provisioning_status": IdentityProvisioningStatus.DISABLED.value
    }


def test_identity_node_blocks_without_runtime_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.identity_provisioning.get_settings",
        lambda: SimpleNamespace(identity_provisioning_enabled=True),
    )
    output = identity_provisioning_node({"signup_forms_detected": [{"target_signup_url": "https://app.example.test/signup"}]})
    assert output["identity_provisioning_status"] == IdentityProvisioningStatus.BLOCKED.value
    assert "agent_not_configured" in output["errors"][0]


def test_identity_node_returns_only_report_safe_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.identity_provisioning.get_settings",
        lambda: SimpleNamespace(identity_provisioning_enabled=True),
    )
    agent = IdentityProvisioningAgent(
        submit_signup=lambda _request, _email, _password: True,
        watcher=EmailVerificationWatcher(
            lambda submitted: VerificationMaterialFound(
                correlation_id=submitted.correlation_id,
                target_origin="https://app.example.test/verify",
                material_type="link",
                material_ref="vault://eng-identity/mail/event-node",
                event_ref="mail-event-node",
            )
        ),
        complete_verification=lambda _submitted, _material: True,
        mailbox_ref="vault://eng-identity/mailbox",
    )
    state = {
        "engagement_id": "eng-identity",
        "client_id": "client-a",
        "signup_forms_detected": [_event().model_dump(mode="json")],
        "runtime_context": SimpleNamespace(
            identity_provisioning_agent=agent,
            engagement_scope=_scope(),
        ),
    }
    output = identity_provisioning_node(state)
    assert output["identity_provisioning_status"] == IdentityProvisioningStatus.VERIFIED.value
    assert output["identity_records"]
    rendered = str(output).lower()
    assert "raw-secret" not in rendered
    assert "password=" not in rendered
    assert "\"password\":" not in rendered
    assert "otp=" not in rendered


def test_identity_node_rejects_malformed_secret_form_without_calling_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "webpent.shared.identity_provisioning.get_settings",
        lambda: SimpleNamespace(identity_provisioning_enabled=True),
    )
    calls = 0

    class Agent:
        def provision(self, _form: object, _scope: object) -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"status": IdentityProvisioningStatus.VERIFIED.value}

    state = {
        "engagement_id": "eng-identity",
        "client_id": "client-a",
        "signup_forms_detected": [
            {
                "engagement_id": "eng-identity",
                "client_id": "client-a",
                "target_signup_url": "https://app.example.test/signup",
                "password": "raw-secret",
            }
        ],
        "runtime_context": SimpleNamespace(
            identity_provisioning_agent=Agent(),
            engagement_scope=_scope(),
        ),
    }
    output = identity_provisioning_node(state)
    assert output["identity_provisioning_status"] == IdentityProvisioningStatus.BLOCKED.value
    assert calls == 0
    assert "raw-secret" not in str(output)


def test_verification_material_rejects_raw_secret_fields() -> None:
    with pytest.raises(ValueError, match="raw_verification_material_rejected"):
        VerificationMaterialFound(
            correlation_id="corr-valid-000000000000",
            target_origin="https://app.example.test/verify",
            material_type="otp",
            material_ref="vault://eng-identity/mail/event-3",
            event_ref="mail-event-3",
            otp="123456",
        )
