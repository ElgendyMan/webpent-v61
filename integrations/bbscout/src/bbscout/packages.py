"""Versioned target-package construction and offline verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import IntegrityError
from .integrity import find_secret_paths, package_digest, sha256_json, verify_package_digest
from .models import CapabilityProfile, ProgramSummary, ScopeAssessment, ScoreBreakdown, utc_now

PACKAGE_VERSION = "target-package.schema.v2"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def build_target_package(
    *,
    program: ProgramSummary,
    scope: ScopeAssessment,
    score: ScoreBreakdown,
    profile: CapabilityProfile,
    raw_sources: dict[str, Any],
    confirmed_by_user: bool,
    expires_in_hours: int = 168,
) -> dict[str, Any]:
    """Build a package only for a user-confirmed eligible program.

    This function creates no detached cryptographic signature; it marks that state
    explicitly so downstream code cannot assume one exists.
    """
    if not confirmed_by_user:
        raise IntegrityError("لازم تأكيد صريح من المستخدم قبل بناء Target Package.")
    if score.eligibility != "eligible" or score.score is None:
        raise IntegrityError("البرنامج غير مؤهل؛ ممنوع بناء package قابلة للتشغيل.")
    if scope.status != "ready":
        raise IntegrityError(f"حالة الـ scope هي {scope.status}؛ ممنوع بناء package ready.")

    raw_secret_paths = find_secret_paths(raw_sources)
    if raw_secret_paths:
        raise IntegrityError("فشل فحص الأسرار في source evidence: " + ", ".join(raw_secret_paths))

    retrieved_at = utc_now()
    expires_at = (
        (datetime.now(UTC) + timedelta(hours=expires_in_hours))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    source_hash = sha256_json(raw_sources)
    package_id = sha256_json(
        {
            "provider": program.provider,
            "program_id": program.program_id,
            "retrieved_at": retrieved_at,
            "source_hash": source_hash,
        }
    )
    package: dict[str, Any] = {
        "package_id": package_id,
        "schema_version": PACKAGE_VERSION,
        "package_version": PACKAGE_VERSION,
        "package_status": "ready",
        "provider": program.provider,
        "program_id": program.program_id,
        "program_handle": program.handle,
        "program_name": program.name,
        "program": {
            "stable_program_id": program.program_id,
            "handle": program.handle,
            "name": program.name,
            "status": program.status,
            "visibility": program.visibility,
        },
        "source": {
            "retrieved_at": retrieved_at,
            "policy_url": program.source_url,
            "scope_url": program.source_url,
            "source_url": program.source_url,
            "source_response_sha256": source_hash,
            "provider_schema_version": "adapter-controlled",
            "adapter_version": raw_sources.get("adapter_version", "unknown"),
        },
        "authorization": {
            "user_confirmed": True,
            "confirmed_at": retrieved_at,
            "package_expires_at": expires_at,
            "expiry": expires_at,
            "revoked": False,
            "revocation_state": "active",
            "package_state": "ready",
            "read_only_discovery": True,
        },
        "scope": {
            "status": scope.status,
            "include_count": scope.include_count,
            "exclusion_count": scope.exclusion_count,
            "warnings": scope.warnings,
            "normalized_rules": [rule.__dict__ for rule in scope.normalized_rules],
            "redirect_policy": (
                "Every redirect destination must independently match a ready package rule."
            ),
            "wildcard_policy": (
                "Wildcard includes subdomains only; apex requires an explicit include rule."
            ),
        },
        "policy": {
            "policy_url": program.source_url,
            "raw_policy_sha256": sha256_json(program.policy_text or ""),
            "policy_present": bool(program.policy_text),
            "safe_harbor": "provider_policy_source_only",
            "prohibited_actions": [
                "out_of_scope_testing",
                "destructive_actions",
                "provider_submission",
            ],
            "required_headers": [],
            "rate_limits": {},
            "enforcement_state": "reviewed_as_provider_source_only",
        },
        "capability_profile": {
            "profile_version": profile.profile_version,
            "qualified_capabilities": profile.qualified_capabilities,
            "validators": profile.validators,
            "confirmation": profile.confirmation,
            "generated_at": profile.generated_at,
        },
        "selection": {
            "score": score.score,
            "confidence": score.confidence,
            "uncertainty_interval": [score.uncertainty_low, score.uncertainty_high],
            "reasons": score.reasons,
            "features": score.features,
            "ranking_model_version": "bbscout-score-v1",
        },
        "integrity": {
            "content_sha256": None,
            "detached_signature": None,
            "signature_state": "unsigned-local-mvp",
        },
        "redaction": {
            "secret_scan": "pending",
            "artifact_classification": "internal-authorized-target-metadata",
            "redaction_version": "bbscout-redaction-v1",
        },
        "provenance": {
            "normalization_version": "bbscout-normalization-v1",
            "source_references": [program.source_url] if program.source_url else [],
            "normalization_decisions": [
                "scope_rules_normalized_by_bbscout",
                "provider_metadata_is_not_execution_authority",
            ],
        },
    }
    secret_paths = find_secret_paths(package)
    if secret_paths:
        raise IntegrityError("فشل فحص الأسرار في مرحلة البناء: " + ", ".join(secret_paths))
    package["redaction"]["secret_scan"] = "passed"
    package["integrity"]["content_sha256"] = package_digest(package)
    return package


def verify_target_package(
    package: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    """Offline, fail-closed package verification suitable for WebPent preflight."""
    required = {
        "package_version",
        "package_status",
        "provider",
        "program",
        "source",
        "authorization",
        "scope",
        "policy",
        "capability_profile",
        "selection",
        "integrity",
        "redaction",
    }
    missing = sorted(required - package.keys())
    if missing:
        raise IntegrityError("حقول package ناقصة: " + ", ".join(missing))
    if package["package_version"] != PACKAGE_VERSION:
        raise IntegrityError("نسخة package غير مدعومة.")
    if package["package_status"] != "ready":
        raise IntegrityError("package ليست بحالة ready.")
    if not package["authorization"].get("user_confirmed"):
        raise IntegrityError("package غير مؤكدة من المستخدم.")
    if package["authorization"].get("revoked"):
        raise IntegrityError("package تم إلغاؤها.")
    if package["scope"].get("status") != "ready":
        raise IntegrityError("scope ليست ready.")
    if package["redaction"].get("secret_scan") != "passed":
        raise IntegrityError("Secret scan لم ينجح.")
    expires_at = _parse_time(str(package["authorization"].get("package_expires_at", "")))
    now = now or datetime.now(UTC)
    if expires_at <= now:
        raise IntegrityError("package انتهت صلاحيتها.")
    verify_package_digest(package)
    return {
        "valid": True,
        "provider": package["provider"],
        "program": package["program"]["handle"],
        "expires_at": package["authorization"]["package_expires_at"],
        "content_sha256": package["integrity"]["content_sha256"],
        "signature_state": package["integrity"]["signature_state"],
        "warning": "هذه نسخة MVP غير موقعة بتوقيع detached؛ تحقق الـ hash محلي فقط.",
    }
