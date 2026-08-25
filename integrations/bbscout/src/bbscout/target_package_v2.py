"""Strict, offline Target Package v2 contract helpers.

This module is intentionally transport-free. It verifies package structure,
local integrity, freshness, revocation and redaction without treating provider
metadata as permission to execute an action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .integrity import find_secret_paths, verify_package_digest
from .signatures import verify_detached_signature

SCHEMA_VERSION = "target-package.schema.v2"
PACKAGE_STATES = frozenset(
    {
        "draft",
        "retrieved",
        "normalized",
        "needs_review",
        "scope_ambiguous",
        "partial_scope",
        "stale",
        "revoked",
        "expired",
        "verified",
        "confirmed",
        "ready",
        "consumed",
        "invalid",
    }
)


@dataclass(frozen=True)
class TargetPackageV2:
    package_id: str
    schema_version: str
    provider: str
    program_id: str
    program_handle: str
    program_name: str
    package_status: str
    source: Mapping[str, Any]
    authorization: Mapping[str, Any]
    policy: Mapping[str, Any]
    scope: Mapping[str, Any]
    capability_profile: Mapping[str, Any]
    selection: Mapping[str, Any]
    integrity: Mapping[str, Any]
    redaction: Mapping[str, Any]
    provenance: Mapping[str, Any]
    raw: Mapping[str, Any]

    @classmethod
    def from_dict(cls, package: Mapping[str, Any]) -> TargetPackageV2:
        program = package.get("program") if isinstance(package.get("program"), Mapping) else {}
        schema_version = str(package.get("schema_version") or package.get("package_version") or "")
        return cls(
            package_id=str(package.get("package_id") or ""),
            schema_version=schema_version,
            provider=str(package.get("provider") or ""),
            program_id=str(package.get("program_id") or program.get("stable_program_id") or ""),
            program_handle=str(package.get("program_handle") or program.get("handle") or ""),
            program_name=str(package.get("program_name") or program.get("name") or ""),
            package_status=str(package.get("package_status") or ""),
            source=dict(package.get("source") or {}),
            authorization=dict(package.get("authorization") or {}),
            policy=dict(package.get("policy") or {}),
            scope=dict(package.get("scope") or {}),
            capability_profile=dict(package.get("capability_profile") or {}),
            selection=dict(package.get("selection") or {}),
            integrity=dict(package.get("integrity") or {}),
            redaction=dict(package.get("redaction") or {}),
            provenance=dict(package.get("provenance") or {}),
            raw=dict(package),
        )

    def validate_shape(self) -> list[str]:
        errors: list[str] = []
        required_values = {
            "package_id": self.package_id,
            "schema_version": self.schema_version,
            "provider": self.provider,
            "program_id": self.program_id,
            "program_handle": self.program_handle,
            "program_name": self.program_name,
        }
        errors.extend(f"{name}_missing" for name, value in required_values.items() if not value)
        if self.schema_version != SCHEMA_VERSION:
            errors.append("unsupported_schema_version")
        if self.package_status not in PACKAGE_STATES:
            errors.append("invalid_package_status")
        for name, value in (
            ("source", self.source),
            ("authorization", self.authorization),
            ("policy", self.policy),
            ("scope", self.scope),
            ("capability_profile", self.capability_profile),
            ("selection", self.selection),
            ("integrity", self.integrity),
            ("redaction", self.redaction),
            ("provenance", self.provenance),
        ):
            if not value:
                errors.append(f"{name}_missing")
        if self.scope.get("status") != "ready":
            errors.append("scope_not_ready")
        if self.redaction.get("secret_scan") != "passed":
            errors.append("secret_scan_not_passed")
        if not self.authorization.get("user_confirmed"):
            errors.append("missing_user_confirmation")
        if (
            bool(self.authorization.get("revoked"))
            or self.authorization.get("revocation_state") == "revoked"
        ):
            errors.append("package_revoked")
        return errors


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    package_id: str | None = None
    package_digest: str | None = None
    signature_state: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "package_id": self.package_id,
            "package_digest": self.package_digest,
            "signature_state": self.signature_state,
        }


def _parse_time(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def validate_target_package(
    package: Mapping[str, Any],
    *,
    now: datetime | None = None,
    require_detached_signature: bool = False,
    trusted_public_keys: Mapping[str, Any] | None = None,
) -> ValidationResult:
    """Validate a package without performing any target or provider I/O."""
    typed = TargetPackageV2.from_dict(package)
    errors = list(typed.validate_shape())
    warnings: list[str] = []
    now = now or datetime.now(UTC)
    try:
        expires_at = _parse_time(
            typed.authorization.get("package_expires_at") or typed.authorization.get("expiry")
        )
        if expires_at <= now:
            errors.append("package_expired")
    except (TypeError, ValueError):
        errors.append("invalid_expiry")
    try:
        verify_package_digest(dict(package))
    except Exception:
        errors.append("content_hash_mismatch")
    secret_paths = find_secret_paths(dict(package))
    if secret_paths:
        errors.append("secrets_detected")
    signature_state = str(typed.integrity.get("signature_state") or "missing")
    if require_detached_signature:
        if signature_state != "verified":
            errors.append("detached_signature_not_verified")
        elif not trusted_public_keys:
            errors.append("trusted_signature_key_missing")
        else:
            try:
                verify_detached_signature(dict(package), trusted_public_keys=trusted_public_keys)
            except Exception:
                errors.append("detached_signature_invalid")
    elif signature_state != "verified":
        warnings.append("detached_signature_not_verified_local_hash_only")
    package_digest = str(typed.integrity.get("content_sha256") or "") or None
    return ValidationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        warnings=tuple(dict.fromkeys(warnings)),
        package_id=typed.package_id or None,
        package_digest=package_digest,
        signature_state=signature_state,
    )
