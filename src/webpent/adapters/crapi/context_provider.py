"""Offline crAPI adapter for generic context and fixture contracts.

This module intentionally stops at deterministic descriptors. It does not
create accounts, tokens, credentials, application objects, or live requests.
"""

from __future__ import annotations

from webpent.adapters.mock_target.context_provider import (
    MockContextProvider,
    MockFixtureProvider,
    MockSessionProvider,
)
from webpent.shared.target_context import (
    FixtureRequest,
    IdentityRequest,
    SessionHandle,
    TargetScope,
)

CRAPI_TARGET_SPEC_ID = "crapi-target-spec"
CRAPI_OFFLINE_CAPABILITIES = frozenset(
    {"read_only_navigation", "context_snapshot", "context_restore", "context_disposal"}
)


class CrAPIContextProvider(MockContextProvider):
    """Offline target context provider; live auth remains explicitly unsupported."""

    def capabilities(self) -> set[str]:
        return set(CRAPI_OFFLINE_CAPABILITIES)


class CrAPISyntheticSessionProvider(MockSessionProvider):
    """Synthetic requester/owner metadata only; no JWT/API key is produced."""

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle:
        session = super().create_synthetic_context(request)
        return SessionHandle(
            session_ref="crapi-offline-session-" + request.identity_ref,
            identity=session.identity,
            in_memory_only=True,
            ready=session.ready,
            reason=session.reason,
        )


class CrAPIObjectFixtureProvider(MockFixtureProvider):
    """Disposable object-access descriptors for offline contract tests."""

    def provision(self, fixture_request: FixtureRequest):
        return super().provision(fixture_request)


def crapi_scope(
    campaign_id: str = "crapi-context-campaign",
    run_id: str = "crapi-context-run",
) -> TargetScope:
    return TargetScope(
        CRAPI_TARGET_SPEC_ID,
        campaign_id,
        run_id,
        "http://127.0.0.1:8888",
        "crapi-scope",
    )


__all__ = [
    "CRAPI_OFFLINE_CAPABILITIES",
    "CRAPI_TARGET_SPEC_ID",
    "CrAPIContextProvider",
    "CrAPISyntheticSessionProvider",
    "CrAPIObjectFixtureProvider",
    "crapi_scope",
]
