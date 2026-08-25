"""Read-only provider contract.

A CredentialRef contains an environment-variable name, never the credential value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..models import ProgramSummary, ScopeAsset


@dataclass(frozen=True)
class CredentialRef:
    username_env: str | None = None
    token_env: str | None = None


@dataclass(frozen=True)
class ProviderHealth:
    provider: str
    healthy: bool
    detail: str
    adapter_version: str


class BugBountyProvider(Protocol):
    provider_name: str
    adapter_version: str

    def health_check(self) -> ProviderHealth: ...

    def list_accessible_programs(self) -> list[ProgramSummary]: ...

    def get_program(self, handle: str) -> ProgramSummary: ...

    def get_scope(self, handle: str) -> list[ScopeAsset]: ...

    def get_policy(self, handle: str) -> str | None: ...
