"""Shared test bootstrap for deterministic local crypto dependencies.

Production defaults remain blank and fail closed. These values exist only in
pytest's process so legacy vault/JWT behavior tests exercise configured crypto
rather than silently disabling the feature under test.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def configured_test_secrets(monkeypatch: pytest.MonkeyPatch):
    from webpent.config.settings import get_settings

    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-" + "j" * 48)
    monkeypatch.setenv("AUDIT_SECRET_KEY", "test-audit-secret-" + "a" * 48)
    monkeypatch.setenv(
        "CELERY_PAYLOAD_KEY",
        "test-celery-payload-secret-" + "c" * 48,
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
