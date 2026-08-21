"""Production secret defaults must fail closed before application startup."""

import pytest
from pydantic import ValidationError

from webpent.config.settings import (
    EnvironmentProfile,
    Settings,
    deployment_requires_proof_bundle,
)

_STRONG = "x" * 48


def _secure_production_kwargs() -> dict[str, object]:
    return {
        "environment_profile": "production",
        "auth_enabled": True,
        "jwt_secret_key": _STRONG,
        "audit_secret_key": _STRONG,
        "celery_payload_key": _STRONG,
        "cors_origins": ["https://app.example.com"],
        "rate_limit_enabled": True,
        "rate_limit_redis_url": "rediss://redis.example.com:6380/0",
        "allow_insecure_tls": False,
    }


@pytest.mark.parametrize(
    ("field", "insecure_value", "message"),
    [
        (
            "jwt_secret_key",
            "webpent-dev-secret-key-change-in-production",
            "JWT",
        ),
        (
            "audit_secret_key",
            "webpent-dev-audit-key-change-in-production",
            "audit",
        ),
        (
            "celery_payload_key",
            "webpent-dev-celery-payload-key-change-in-production",
            "celery_payload_key",
        ),
    ],
)
def test_production_rejects_known_default_secret(
    field: str, insecure_value: str, message: str
) -> None:
    kwargs = _secure_production_kwargs()
    kwargs[field] = insecure_value

    with pytest.raises(ValidationError, match=message):
        Settings(**kwargs)


def test_non_lab_requires_proof_bundle_even_without_opt_in() -> None:
    assert deployment_requires_proof_bundle(EnvironmentProfile.LAB) is False
    assert deployment_requires_proof_bundle(EnvironmentProfile.STAGING) is True
    assert deployment_requires_proof_bundle(EnvironmentProfile.PRODUCTION) is True
    assert deployment_requires_proof_bundle("future-profile") is True


def test_non_lab_profile_cannot_disable_authentication() -> None:
    with pytest.raises(ValidationError, match="auth_enabled=True"):
        Settings(environment_profile="production", auth_enabled=False)
