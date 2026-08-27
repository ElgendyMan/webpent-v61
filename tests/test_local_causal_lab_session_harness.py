from __future__ import annotations

from dataclasses import replace

import pytest

from webpent.adapters.local_causal_lab.session_harness import (
    OpaqueSessionDescriptor,
    build_offline_harness,
    harness_snapshot_restore_check,
)


def test_offline_harness_reaches_explicit_offline_readiness() -> None:
    result = harness_snapshot_restore_check("owasp_webgoat")
    assert result["preconditions_ready"] is True
    assert result["fixture_ready"] is True
    assert result["identity_model_ready"] is True
    assert result["reset_verified"] is True
    assert result["runtime_digest_verified"] is True
    assert result["network_scope_verified"] is True
    assert result["network_attempted"] is False
    assert result["target_fixture_injected"] is False
    assert result["errors"] == ()


def test_offline_harness_snapshot_restore_is_deterministic_for_both_targets() -> None:
    for target_id in ("owasp_webgoat", "crapi"):
        harness = build_offline_harness(target_id)
        snapshot = harness.snapshot()
        restored = harness.restore_from_snapshot(snapshot)
        assert restored.snapshot() == snapshot
        assert restored.fixture.state_hash() == harness.fixture.state_hash()
        assert restored.ownership_relation_hash() == harness.ownership_relation_hash()
        assert restored.network_attempted is False


def test_harness_rejects_auth_token_cookie_material() -> None:
    harness = build_offline_harness("crapi")
    credentialed = replace(
        harness.requester_session,
        token_material_present=True,
    )
    invalid = replace(harness, requester_session=credentialed)
    errors = invalid.validate()
    assert "session_auth_material_forbidden" in errors
    with pytest.raises(ValueError, match="harness_snapshot_blocked"):
        invalid.snapshot()


def test_harness_rejects_target_injection_and_network_attempt() -> None:
    harness = build_offline_harness("owasp_webgoat")
    injected = replace(harness, target_fixture_injected=True)
    assert "target_fixture_injection_requires_separate_authorization" in injected.validate()
    assert injected.readiness(
        runtime_digest_verified=True,
        network_scope_verified=True,
    )["preconditions_ready"] is False

    networked = replace(harness, network_attempted=True)
    assert "harness_must_not_attempt_network" in networked.validate()
    assert networked.readiness(
        runtime_digest_verified=True,
        network_scope_verified=True,
    )["preconditions_ready"] is False


def test_harness_rejects_non_opaque_session_descriptor() -> None:
    invalid = OpaqueSessionDescriptor(
        session_id="cookie_value",
        identity_id="alice@example.com",
        purpose="application_session",
    )
    errors = invalid.validate()
    assert "session_id_must_be_opaque" in errors
    assert "session_identity_must_be_opaque_test_id" in errors
    assert "session_purpose_must_be_offline_descriptor" in errors
