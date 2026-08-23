from datetime import UTC, datetime, timedelta

import pytest

from webpent.shared.package_scope import (
    AuthorizationContext,
    ScopeCompiler,
    ScopeDecisionStatus,
)


def _compiler(*rules: dict[str, object]) -> ScopeCompiler:
    return ScopeCompiler(
        AuthorizationContext(
            package_id="pkg-1",
            package_sha256="digest-1",
            scope_digest="scope-1",
            policy_digest="policy-1",
            scope_status="ready",
            scope_rules=tuple(rules),
            policy_constraints={},
            expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            revocation_state="active",
        )
    )


def test_exact_host_does_not_match_suffix_lookalikes() -> None:
    compiler = _compiler(
        {
            "rule_id": "include-example",
            "action": "include",
            "asset_type": "url",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/",
        }
    )

    assert compiler.decide("https://example.com/").status is ScopeDecisionStatus.ALLOW
    for host in ("sub.example.com", "evil-example.com", "example.com.evil.com"):
        decision = compiler.decide(f"https://{host}/")
        assert decision.status is ScopeDecisionStatus.DENY_OUT_OF_SCOPE


def test_wildcard_excludes_base_domain_and_suffix_lookalikes() -> None:
    compiler = _compiler(
        {
            "rule_id": "include-subdomains",
            "action": "include",
            "asset_type": "wildcard",
            "host": "*.example.com",
            "wildcard": True,
            "scheme": "https",
            "port": 443,
            "path": "/",
        }
    )

    assert compiler.decide("https://sub.example.com/").allowed
    assert not compiler.decide("https://example.com/").allowed
    assert not compiler.decide("https://example.com.evil.com/").allowed


@pytest.mark.parametrize("url", [
    "https://example.com/app/../admin",
    "https://example.com/%2e%2e/admin",
])
def test_path_traversal_cannot_escape_included_path(url: str) -> None:
    compiler = _compiler(
        {
            "rule_id": "include-app",
            "action": "include",
            "asset_type": "url",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/app",
        }
    )

    decision = compiler.decide(url)

    assert decision.status is ScopeDecisionStatus.DENY_AMBIGUOUS


def test_query_fragment_userinfo_and_non_http_schemes_are_ambiguous() -> None:
    compiler = _compiler(
        {
            "rule_id": "include-example",
            "action": "include",
            "asset_type": "url",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/",
        }
    )

    for url in (
        "https://example.com/?x=1",
        "https://example.com/#fragment",
        "https://user:pass@example.com/",
        "ws://example.com/",
    ):
        assert (
            compiler.decide(url).status is ScopeDecisionStatus.DENY_AMBIGUOUS
        )


def test_redirect_chain_must_remain_authorized() -> None:
    compiler = _compiler(
        {
            "rule_id": "include-example",
            "action": "include",
            "asset_type": "url",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/",
        }
    )

    decision = compiler.decide(
        "https://example.com/",
        redirect_chain=("https://outside.example/",),
    )

    assert decision.status is ScopeDecisionStatus.DENY_OUT_OF_SCOPE
    assert decision.reason == "redirect_destination_not_authorized"


def test_scope_decision_is_typed_auditable_and_reproducible() -> None:
    compiler = _compiler(
        {
            "rule_id": "include-example",
            "action": "include",
            "asset_type": "url",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/",
        }
    )

    first = compiler.decide("https://example.com/")
    second = compiler.decide("https://example.com/")

    assert first == second
    assert first.allowed
    assert first.as_dict() == {
        "status": "allow",
        "reason": "matched_explicit_include",
        "matched_rule_id": "include-example",
        "constraints": [],
    }
