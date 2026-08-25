from types import SimpleNamespace

import pytest

from webpent.shared import resume_capability


@pytest.fixture
def capability_settings(monkeypatch):
    monkeypatch.setattr(
        resume_capability,
        "get_settings",
        lambda: SimpleNamespace(jwt_secret_key="p1-test-secret-" + "x" * 32),
    )


def _record() -> dict[str, str]:
    return {
        "owner_username": "alice",
        "client_id": "client-a",
        "engagement_id": "eng-a",
    }


def _issue() -> str:
    return resume_capability.issue_resume_capability(
        thread_id="thread-a",
        owner_username="alice",
        client_id="client-a",
        engagement_id="eng-a",
    )


def test_detailed_verifier_accepts_valid_capability(capability_settings):
    assert resume_capability.verify_resume_capability_detailed(
        _issue(), thread_id="thread-a", record=_record()
    ) == (True, "valid")


def test_detailed_verifier_reports_invalid_signature(capability_settings):
    token = _issue()
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]

    assert resume_capability.verify_resume_capability_detailed(
        ".".join(parts), thread_id="thread-a", record=_record()
    ) == (False, "invalid_signature_or_format")


def test_detailed_verifier_reports_binding_mismatch(capability_settings):
    assert resume_capability.verify_resume_capability_detailed(
        _issue(), thread_id="other-thread", record=_record()
    ) == (False, "binding_mismatch_thread_id")


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("owner_username", "bob", "binding_mismatch_owner_username"),
        ("client_id", "client-b", "binding_mismatch_client_id"),
        ("engagement_id", "eng-b", "binding_mismatch_engagement_id"),
    ],
)
def test_detailed_verifier_reports_identity_mismatch(
    capability_settings, field, value, expected
):
    record = _record()
    record[field] = value
    assert resume_capability.verify_resume_capability_detailed(
        _issue(), thread_id="thread-a", record=record
    ) == (False, expected)


def test_detailed_verifier_reports_expired_capability(capability_settings, monkeypatch):
    now = 1_700_000_000
    monkeypatch.setattr(resume_capability.time, "time", lambda: now)
    token = resume_capability.issue_resume_capability(
        thread_id="thread-a",
        owner_username="alice",
        client_id="client-a",
        engagement_id="eng-a",
        ttl_seconds=1,
    )
    monkeypatch.setattr(resume_capability.time, "time", lambda: now + 2)

    assert resume_capability.verify_resume_capability_detailed(
        token, thread_id="thread-a", record=_record()
    ) == (False, "expired_capability")


def test_detailed_verifier_classifies_malformed_input(capability_settings):
    assert resume_capability.verify_resume_capability_detailed(
        "v1.%%%.%%%", thread_id="thread-a", record=_record()
    ) == (False, "invalid_signature_or_format")


def test_backward_compatible_boolean_verifier(capability_settings):
    token = _issue()
    assert resume_capability.verify_resume_capability(
        token, thread_id="thread-a", record=_record()
    ) is True
    assert resume_capability.verify_resume_capability(
        token, thread_id="other-thread", record=_record()
    ) is False


# No network, browser, queue, filesystem, or target actions are performed here.
