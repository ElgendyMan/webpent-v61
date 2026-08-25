"""Provider-neutral typed models for bbscout.

These models deliberately preserve uncertainty. An unknown or ambiguous value must
never silently become authorization for a target action.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

UTC = timezone.utc


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ProviderName(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"


class AssetType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"
    MOBILE = "mobile"
    SOURCE = "source"
    OTHER = "other"


class ScopeStatus(str, Enum):
    READY = "ready"
    PARTIAL = "partial_scope"
    AMBIGUOUS = "scope_ambiguous"
    STALE = "stale"
    INVALID = "invalid_scope"


class PackageStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


class EligibilityStatus(str, Enum):
    ELIGIBLE = "eligible"
    REVIEW = "review"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ProgramSummary:
    provider: str
    program_id: str
    handle: str
    name: str
    status: str
    visibility: str = "unknown"
    updated_at: str | None = None
    access_state: str = "visible"
    tags: list[str] = field(default_factory=list)
    policy_text: str | None = None
    source_url: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ProgramSummary:
        return cls(**value)


@dataclass(frozen=True)
class ScopeAsset:
    asset_id: str
    asset_type: str
    value: str
    included: bool
    eligible_for_submission: bool | None = None
    instruction: str | None = None
    updated_at: str | None = None
    source_id: str | None = None
    source_url: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ScopeAsset:
        return cls(**value)


@dataclass(frozen=True)
class NormalizedRule:
    rule_id: str
    action: str
    asset_type: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    wildcard: bool
    raw_value: str
    decision_reason: str
    source_asset_id: str


@dataclass(frozen=True)
class ScopeAssessment:
    status: str
    normalized_rules: list[NormalizedRule]
    warnings: list[str]
    exclusion_count: int
    include_count: int
    assessed_at: str


@dataclass(frozen=True)
class CapabilityProfile:
    profile_version: str
    qualified_capabilities: dict[str, bool]
    validators: dict[str, bool]
    confirmation: dict[str, bool]
    generated_at: str = field(default_factory=utc_now)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CapabilityProfile:
        return cls(
            profile_version=str(value.get("profile_version", "unknown")),
            qualified_capabilities=dict(value.get("qualified_capabilities", {})),
            validators=dict(value.get("validators", {})),
            confirmation=dict(value.get("confirmation", {})),
            generated_at=str(value.get("generated_at", utc_now())),
        )


@dataclass(frozen=True)
class ScoreBreakdown:
    score: float | None
    confidence: str
    uncertainty_low: float | None
    uncertainty_high: float | None
    eligibility: str
    reasons: list[str]
    blockers: list[str]
    features: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class TargetPackage:
    package_version: str
    package_status: str
    provider: str
    program: dict[str, Any]
    source: dict[str, Any]
    authorization: dict[str, Any]
    scope: dict[str, Any]
    policy: dict[str, Any]
    capability_profile: dict[str, Any]
    selection: dict[str, Any]
    integrity: dict[str, Any]
    redaction: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def dataclass_to_dict(value: Any) -> Any:
    """Safely convert nested dataclasses and enums for deterministic JSON."""
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {k: dataclass_to_dict(v) for k, v in asdict(value).items()}
    if isinstance(value, list):
        return [dataclass_to_dict(item) for item in value]
    if isinstance(value, dict):
        return {str(k): dataclass_to_dict(v) for k, v in value.items()}
    return value
