"""Canonical, target-neutral workflow identifiers.

Adapters may expose a compatibility mapping from legacy target-local identifiers
into these values. The shared runner depends only on these generic concepts and
never on a target's historical workflow names.
"""
from __future__ import annotations

from typing import Final

READ_ONLY_NAVIGATION: Final[str] = "read_only_navigation"
TYPED_SEARCH: Final[str] = "typed_search"
AUTHORIZED_API_REQUEST: Final[str] = "authorized_api_request"
BROWSER_OBSERVATION: Final[str] = "browser_observation"

CANONICAL_WORKFLOW_IDS: Final[frozenset[str]] = frozenset(
    {
        READ_ONLY_NAVIGATION,
        TYPED_SEARCH,
        AUTHORIZED_API_REQUEST,
        BROWSER_OBSERVATION,
    }
)

__all__ = [
    "AUTHORIZED_API_REQUEST",
    "BROWSER_OBSERVATION",
    "CANONICAL_WORKFLOW_IDS",
    "READ_ONLY_NAVIGATION",
    "TYPED_SEARCH",
]
