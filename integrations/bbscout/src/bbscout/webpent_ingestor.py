"""Safe handoff boundary for a future WebPent ActionAuthority.

This module performs only offline verification and local scope decisions.  It does
not create HTTP clients, browsers, DNS requests, subprocesses, or engagements.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import PolicyViolationError
from .integrity import read_json
from .models import NormalizedRule, ScopeAssessment
from .packages import verify_target_package
from .scope import decision_for_url
from .target_package_v2 import ValidationResult, validate_target_package


@dataclass(frozen=True)
class AuthorizationContext:
    provider: str
    program_handle: str
    package_sha256: str
    scope: ScopeAssessment
    expires_at: str


class TargetPackageIngestor:
    """Verify a package and expose fail-closed authorization checks to WebPent."""

    def ingest(self, package_path: str | Path) -> AuthorizationContext:
        package = read_json(package_path)
        validation = validate_target_package(package)
        if not validation.valid:
            raise PolicyViolationError(
                "Target Package v2 غير صالح: " + ", ".join(validation.errors)
            )
        verify_target_package(package)
        scope_data = package["scope"]
        rules = [NormalizedRule(**rule) for rule in scope_data["normalized_rules"]]
        scope = ScopeAssessment(
            status=scope_data["status"],
            normalized_rules=rules,
            warnings=list(scope_data.get("warnings", [])),
            exclusion_count=int(scope_data.get("exclusion_count", 0)),
            include_count=int(scope_data.get("include_count", 0)),
            assessed_at=str(package["source"]["retrieved_at"]),
        )
        return AuthorizationContext(
            provider=str(package["provider"]),
            program_handle=str(package.get("program_handle") or package["program"]["handle"]),
            package_sha256=str(package["integrity"]["content_sha256"]),
            scope=scope,
            expires_at=str(
                package["authorization"].get("package_expires_at")
                or package["authorization"]["expiry"]
            ),
        )

    def validate(self, package_path: str | Path) -> ValidationResult:
        """Return structured offline validation without exposing package secrets."""
        return validate_target_package(read_json(package_path))

    @staticmethod
    def authorize_url(context: AuthorizationContext, candidate_url: str) -> None:
        allowed, reason = decision_for_url(context.scope, candidate_url)
        if not allowed:
            raise PolicyViolationError(
                f"Action مرفوض للـ URL: {candidate_url}. "
                f"السبب: {reason}. package={context.package_sha256}"
            )
