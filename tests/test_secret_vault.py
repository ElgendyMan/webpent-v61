from datetime import timedelta

import pytest

from webpent.shared.secret_vault import SecretVault, SecretVaultError


def test_secret_vault_returns_opaque_engagement_bound_ref() -> None:
    vault = SecretVault()
    ref = vault.put(
        "otp-value-123456",
        engagement_id="eng-1",
        secret_type="otp",
        ttl=timedelta(minutes=1),
    )
    assert ref.ref.startswith("vault://otp/")
    assert "otp-value" not in repr(ref.model_dump())
    assert vault.get(ref, engagement_id="eng-1") == "otp-value-123456"
    with pytest.raises(SecretVaultError, match="secret_engagement_mismatch"):
        vault.get(ref, engagement_id="eng-2")


def test_secret_vault_consume_is_one_time_and_revoke_is_idempotent() -> None:
    vault = SecretVault()
    ref = vault.put("token", engagement_id="eng-1", secret_type="token")
    assert vault.consume(ref, engagement_id="eng-1") == "token"
    with pytest.raises(SecretVaultError, match="secret_ref_not_found"):
        vault.get(ref, engagement_id="eng-1")
    assert vault.revoke(ref, engagement_id="eng-1") is False


def test_secret_vault_rejects_unbounded_ttl_and_expired_refs() -> None:
    vault = SecretVault(max_ttl=timedelta(minutes=1))
    with pytest.raises(ValueError, match="secret_ttl_out_of_bounds"):
        vault.put("token", engagement_id="eng-1", secret_type="token", ttl=timedelta(minutes=2))
    ref = vault.put("token", engagement_id="eng-1", secret_type="token", ttl=timedelta(seconds=1))
    assert ref.expires_at > ref.created_at


def test_secret_vault_rejects_invalid_values() -> None:
    vault = SecretVault()
    with pytest.raises(ValueError, match="secret_value_invalid"):
        vault.put("", engagement_id="eng-1", secret_type="token")
    with pytest.raises(ValueError, match="secret_ref_binding_required"):
        vault.put("token", engagement_id="", secret_type="token")
