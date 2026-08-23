from datetime import UTC, datetime, timedelta

import pytest

from webpent.shared.action_authority import ActionAuthority, ActionRequest
from webpent.shared.target_package_context import (
    TargetPackageAdmissionError,
    admit_target_package,
    assert_package_continuity,
)


def _package_digest(package):
    return pytest.importorskip(
        "bbscout.integrity",
        reason="optional bbscout integration source is not available in this checkout",
    ).package_digest(package)


def package_fixture(**overrides):
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    package = {
        "package_id": "pkg-acme-001",
        "schema_version": "target-package.schema.v2",
        "provider": "fixture",
        "program_id": "program-acme",
        "program_handle": "acme-api",
        "program_name": "Acme API",
        "package_status": "ready",
        "source": {
            "retrieved_at": "2026-08-22T00:00:00Z",
            "source_response_sha256": "a" * 64,
        },
        "authorization": {
            "user_confirmed": True,
            "package_expires_at": expires,
            "revoked": False,
            "revocation_state": "active",
        },
        "policy": {"policy_present": True},
        "scope": {
            "status": "ready",
            "normalized_rules": [
                {"kind": "host", "value": "api.acme.example", "include": True}
            ],
            "redirect_policy": "same-package",
            "wildcard_policy": "explicit",
        },
        "capability_profile": {
            "profile_version": "v1",
            "qualified_capabilities": {"http_read": True},
        },
        "selection": {"selected": True},
        "integrity": {
            "content_sha256": "a" * 64,
            "signature_state": "unsigned-local-mvp",
        },
        "redaction": {"secret_scan": "passed"},
        "provenance": {"normalization_version": "v1", "source_references": []},
    }
    package.update(overrides)
    package.setdefault("integrity", {})["content_sha256"] = _package_digest(package)
    return package


def test_admission_returns_redaction_safe_projection_and_digests():
    context = admit_target_package(package_fixture())
    projected = context.as_state()
    assert projected["package_id"] == "pkg-acme-001"
    assert projected["scope_digest"]
    assert "source" not in projected
    assert "authorization" not in projected


def test_admission_rejects_expired_revoked_or_secret_bearing_packages():
    expired = package_fixture()
    expired["authorization"]["package_expires_at"] = "2020-01-01T00:00:00Z"
    expired["integrity"]["content_sha256"] = _package_digest(expired)
    with pytest.raises(TargetPackageAdmissionError, match="package_expired"):
        admit_target_package(expired)

    revoked = package_fixture()
    revoked["authorization"]["revocation_state"] = "revoked"
    revoked["integrity"]["content_sha256"] = _package_digest(revoked)
    with pytest.raises(TargetPackageAdmissionError, match="package_revoked"):
        admit_target_package(revoked)

    secret = package_fixture()
    secret["provider_secret"] = "must-not-enter-state"
    secret["integrity"]["content_sha256"] = _package_digest(secret)
    with pytest.raises(TargetPackageAdmissionError, match="secret_like"):
        admit_target_package(secret)


def test_continuity_rejects_package_identity_or_digest_drift():
    context = admit_target_package(package_fixture())
    assert_package_continuity(
        context,
        {
            "target_package_id": context.package_id,
            "target_package_sha256": context.package_sha256,
        },
    )
    with pytest.raises(TargetPackageAdmissionError, match="continuity_failure"):
        assert_package_continuity(
            context,
            {
                "target_package_id": "other",
                "target_package_sha256": context.package_sha256,
            },
        )


def test_action_authority_requires_package_identity_and_digest_when_enabled():
    context = admit_target_package(package_fixture()).as_state()
    authority = ActionAuthority(
        allowed_origin="https://api.acme.example",
        target_package={"status": "ready", **context},
    )
    request = ActionRequest(
        task_id="task-1",
        engagement_id="eng-1",
        target_url="https://api.acme.example/v1/users",
        metadata={
            "target_package_id": context["package_id"],
            "target_package_sha256": context["package_sha256"],
        },
    )
    decision = authority.authorize(request)
    assert "package:package_id_mismatch" not in decision.reasons
    assert "package:digest_mismatch" not in decision.reasons

    denied = authority.authorize(
        ActionRequest(
            task_id=request.task_id,
            engagement_id=request.engagement_id,
            target_url=request.target_url,
            metadata={},
        )
    )
    assert "package:package_id_mismatch" in denied.reasons
    assert "package:digest_mismatch" in denied.reasons
