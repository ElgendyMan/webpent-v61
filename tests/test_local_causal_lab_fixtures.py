from __future__ import annotations

from dataclasses import replace

import pytest

from webpent.adapters.local_causal_lab.fixtures import (
    DisposableCanary,
    DisposableFixture,
    SyntheticIdentity,
    build_regression_fixture,
)


def test_regression_fixture_is_opaque_disposable_and_hashable() -> None:
    fixture = build_regression_fixture("owasp_webgoat")
    assert fixture.validate() == ()
    before = fixture.state_hash()
    reset = fixture.reset_check(before)
    assert reset["status"] == "verified"
    assert reset["state_hash_equal"] is True
    assert reset["application_reset_endpoint_called"] is False
    assert reset["application_mutation_performed"] is False
    assert reset["raw_values_persisted"] is False


def test_fixture_rejects_credentials_sessions_mutation_and_raw_values() -> None:
    fixture = build_regression_fixture("crapi")
    bad_identity = replace(fixture.identities[0], session_material_present=True)
    bad = replace(
        fixture, identities=(bad_identity, fixture.identities[1]), raw_values_persisted=True
    )
    errors = bad.validate()
    assert "credential_or_session_material_forbidden" in errors
    assert "raw_values_persistence_must_remain_false" in errors

    bad_canary = DisposableCanary("canary_bad", "synthetic", raw_value_persisted=True)
    assert "raw_canary_persistence_forbidden" in bad_canary.validate()


def test_fixture_reset_fails_closed_when_application_state_would_change() -> None:
    fixture = build_regression_fixture("owasp_webgoat")
    before = fixture.state_hash()
    mutated = replace(fixture, application_mutation_performed=True)
    result = mutated.reset_check(before)
    assert result["status"] == "blocked"
    assert result["state_hash_equal"] is False
    assert "application_mutation_must_remain_false" in result["validation_errors"]


def test_identity_ids_cannot_be_real_or_credential_bearing() -> None:
    identity = SyntheticIdentity("alice@example.com", "owner")
    assert "identity_must_be_opaque_test_id" in identity.validate()
    credentialed = SyntheticIdentity("test_subject_x", "owner", credential_material_present=True)
    assert "credential_or_session_material_forbidden" in credentialed.validate()


def test_fixture_snapshot_restore_is_offline_and_hash_equal() -> None:
    fixture = build_regression_fixture("crapi")
    result = fixture.snapshot_restore_check()
    assert result["status"] == "verified"
    assert result["state_hash_equal"] is True
    assert result["network_attempted"] is False
    assert result["application_reset_endpoint_called"] is False
    assert result["application_mutation_performed"] is False
    assert result["raw_values_persisted"] is False


def test_fixture_snapshot_rejects_invalid_identity() -> None:
    fixture = build_regression_fixture("crapi")
    invalid_identity = replace(fixture.identities[0], session_material_present=True)
    invalid = replace(fixture, identities=(invalid_identity, fixture.identities[1]))
    assert "credential_or_session_material_forbidden" in invalid.validate()
    with pytest.raises(ValueError, match="fixture_snapshot_blocked"):
        invalid.snapshot()


def test_fixture_snapshot_rejects_invalid_canary_and_mutation() -> None:
    fixture = build_regression_fixture("owasp_webgoat")
    invalid_canary = DisposableCanary(
        "canary_owner_object", "owner-specific semantic marker", raw_value_persisted=True
    )
    invalid = replace(
        fixture,
        canaries=(invalid_canary, fixture.canaries[1]),
        application_mutation_performed=True,
    )
    assert "raw_canary_persistence_must_remain_false" not in invalid.validate()
    assert "raw_canary_persistence_forbidden" in invalid_canary.validate()
    assert "application_mutation_must_remain_false" in invalid.validate()
    with pytest.raises(ValueError, match="fixture_snapshot_blocked"):
        invalid.snapshot()


def test_fixture_snapshot_restore_rejects_tampered_snapshot() -> None:
    fixture = build_regression_fixture("crapi")
    snapshot = fixture.snapshot()
    tampered = replace(snapshot, state_hash="0" * 64)
    with pytest.raises(ValueError, match="fixture_restore_hash_mismatch"):
        DisposableFixture.restore_from_snapshot(tampered)
