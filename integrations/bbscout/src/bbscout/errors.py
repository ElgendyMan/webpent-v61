"""Typed errors that prevent a provider failure from being mistaken for empty data."""

from __future__ import annotations


class BBScoutError(Exception):
    code = "bbscout_error"

    def __init__(self, message: str, *, request_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.request_id = request_id

    def to_dict(self) -> dict[str, str | None]:
        return {"code": self.code, "message": self.message, "request_id": self.request_id}


class UnauthorizedError(BBScoutError):
    code = "unauthorized"


class ForbiddenError(BBScoutError):
    code = "forbidden"


class NotFoundError(BBScoutError):
    code = "not_found"


class RateLimitedError(BBScoutError):
    code = "rate_limited"


class ProviderUnavailableError(BBScoutError):
    code = "provider_unavailable"


class SchemaChangedError(BBScoutError):
    code = "schema_changed"


class ScopeAmbiguousError(BBScoutError):
    code = "scope_ambiguous"


class PartialScopeError(BBScoutError):
    code = "partial_scope"


class IntegrityError(BBScoutError):
    code = "integrity_failed"


class PolicyViolationError(BBScoutError):
    code = "policy_violation"
