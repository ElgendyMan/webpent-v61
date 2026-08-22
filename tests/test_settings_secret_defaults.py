"""Security regression tests for fail-closed secret defaults."""

from __future__ import annotations

import warnings

import pytest

from webpent.config.settings import EnvironmentProfile, Settings

_STRICT_BASE = {
    "environment_profile": EnvironmentProfile.PRODUCTION,
    "auth_enabled": True,
    "cors_origins": ["https://scanner.example.test"],
    "rate_limit_enabled": True,
    "rate_limit_redis_url": "rediss://redis.example.test:6379/0",
    "allow_insecure_tls": False,
}


def _clear_secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("JWT_SECRET_KEY", "AUDIT_SECRET_KEY", "CELERY_PAYLOAD_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_local_defaults_are_empty_and_do_not_emit_placeholder_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_secret_env(monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        settings = Settings()

    assert settings.jwt_secret_key == ""
    assert settings.audit_secret_key == ""
    assert settings.celery_payload_key == ""
    assert not [warning for warning in caught if "INSECURE" in str(warning.message)]


def test_production_rejects_missing_jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_secret_env(monkeypatch)
    with pytest.raises(ValueError, match="JWT secret"):
        Settings(**_STRICT_BASE)


def test_production_rejects_missing_audit_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_secret_env(monkeypatch)
    values = {
        **_STRICT_BASE,
        "jwt_secret_key": "j" * 32,
    }
    with pytest.raises(ValueError, match="audit secret"):
        Settings(**values)


def test_production_rejects_missing_celery_payload_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_secret_env(monkeypatch)
    values = {
        **_STRICT_BASE,
        "jwt_secret_key": "j" * 32,
        "audit_secret_key": "a" * 32,
    }
    with pytest.raises(ValueError, match="celery_payload_key"):
        Settings(**values)


def test_production_accepts_operator_supplied_secret_values() -> None:
    values = {
        **_STRICT_BASE,
        "jwt_secret_key": "j" * 32,
        "audit_secret_key": "a" * 32,
        "celery_payload_key": "c" * 32,
    }
    settings = Settings(**values)

    assert settings.environment_profile is EnvironmentProfile.PRODUCTION
    assert settings.auth_enabled is True


def test_explicit_legacy_placeholder_warns_in_lab() -> None:
    with pytest.warns(UserWarning, match="INSECURE audit_secret_key"):
        Settings(
            audit_secret_key="webpent-dev-audit-key-change-in-production",
        )
