"""Juice Shop target adapter.

This module owns Juice Shop routes, case bindings, and semantic contracts. The
shared proof machinery remains target agnostic and receives this adapter
explicitly at orchestration time.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from webpent.benchmark.juice_shop_safe_cases import (
    JUICE_SHOP_SAFE_CASES,
    get_juice_shop_safe_case,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
)

JUICE_SHOP_ORIGIN = "http://127.0.0.1:3000"
JUICE_SHOP_SEMANTIC_PROFILES = SemanticProfileRegistry(
    {
        "juice.exposed_metrics.v1": {
            "target_family": "juice_shop",
            "promotable": True,
            "rule": "prometheus_publication",
            "reason": "bounded_prometheus_publication_shape_with_negative_control",
        },
        "juice.error_disclosure.v1": {
            "target_family": "juice_shop",
            "promotable": True,
            "rule": "verbose_server_error",
            "reason": "bounded_verbose_error_shape_with_negative_control",
        },
    }
)

_CASE_SEMANTIC_PROFILES = {
    "juice.exposed_metrics.v1": "juice.exposed_metrics.v1",
    "juice.error_handling.v1": "juice.error_disclosure.v1",
}
_APPROVED_ORACLE_CASES = frozenset(_CASE_SEMANTIC_PROFILES)


class JuiceShopTargetAdapter:
    """Explicit case and semantic registry for the loopback Juice Shop target."""

    target_id = "owasp_juice_shop"
    target_origin = JUICE_SHOP_ORIGIN
    semantic_profiles = JUICE_SHOP_SEMANTIC_PROFILES

    def workflow_ids(self) -> tuple[str, ...]:
        return (
            "juice-shop-mat-search",
            "juice-shop-read-only-navigation",
        )

    def case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in JUICE_SHOP_SAFE_CASES)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        try:
            case = get_juice_shop_safe_case(case_id)
        except KeyError:
            return None
        return TargetCaseBinding(
            case_id=case.case_id,
            operation=case.operation,
            path=case.path,
            oracle_id=case.oracle_id,
            workflow_id=(
                "juice-shop-mat-search"
                if case.operation == "typed_search"
                else "juice-shop-read-only-navigation"
            ),
            semantic_profile=self.semantic_profile_for_case(case.case_id),
            scoring_status=(
                "oracle_approved_partial"
                if case.case_id in _APPROVED_ORACLE_CASES
                else "not_scored"
            ),
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return _CASE_SEMANTIC_PROFILES.get(str(case_id or "").strip())

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == self.target_origin


JUICE_SHOP_TARGET_ADAPTER = JuiceShopTargetAdapter()
JUICE_SHOP_TARGET_REGISTRATION = RegisteredTargetAdapter(
    adapter=JUICE_SHOP_TARGET_ADAPTER,
    source="webpent.benchmark.juice_shop_target_adapter",
    version="1",
    policy_ref="local-loopback-read-only-juice-shop",
    proof_contract="central-causal-negative-sealed-replay-v1",
    metadata={"target_family": "owasp_juice_shop"},
)


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}" + (
        "" if default else f":{port}"
    )


__all__ = [
    "JUICE_SHOP_ORIGIN",
    "JUICE_SHOP_SEMANTIC_PROFILES",
    "JUICE_SHOP_TARGET_ADAPTER",
    "JUICE_SHOP_TARGET_REGISTRATION",
    "JuiceShopTargetAdapter",
]
