from webpent.shared.provider_boundary import (
    ProviderBoundary,
    ProviderConfig,
    TargetPackageGuard,
    TargetPackageIdentity,
)


def _identity() -> TargetPackageIdentity:
    return TargetPackageIdentity(
        package_id="target-1",
        package_sha256="sha256:target",
        scope_digest="sha256:scope",
        policy_digest="sha256:policy",
    )


def test_disabled_provider_uses_fallback_and_never_authorizes() -> None:
    boundary = ProviderBoundary(
        ProviderConfig("provider-1", "model-a", "https://provider.invalid", "ref-1", enabled=False)
    )
    result = boundary.invoke({"prompt": "test", "api_key": "raw-secret"})
    assert result.status == "disabled"
    assert result.fallback_used
    assert not result.can_authorize_action
    assert not result.can_confirm_finding
    assert "raw-secret" not in repr(result.as_dict())


def test_provider_failure_is_advisory_fallback() -> None:
    boundary = ProviderBoundary(
        ProviderConfig("provider-1", "model-a", "https://provider.invalid", "ref-1", enabled=True)
    )

    def failing_adapter(_config: ProviderConfig, _request: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("synthetic")

    result = boundary.invoke({"prompt": "test"}, failing_adapter)
    assert result.status == "fallback"
    assert result.fallback_used
    assert result.reason == "provider_error:RuntimeError"


def test_provider_response_is_redacted_and_stays_advisory() -> None:
    boundary = ProviderBoundary(
        ProviderConfig("provider-1", "model-a", "https://provider.invalid", "ref-1", enabled=True)
    )
    result = boundary.invoke(
        {"prompt": "test"},
        lambda _config, _request: {"recommendation": "check", "password": "secret"},
    )
    assert result.status == "advisory"
    assert "secret" not in repr(result.as_dict())
    assert not result.can_authorize_action
    assert not result.can_confirm_finding


def test_target_package_guard_requires_exact_identity() -> None:
    expected = _identity()
    guard = TargetPackageGuard(expected)
    assert guard.verify(expected)[0]
    changed_scope = TargetPackageIdentity(
        expected.package_id,
        expected.package_sha256,
        "sha256:other-scope",
        expected.policy_digest,
    )
    ok, reason = guard.verify(changed_scope)
    assert not ok
    assert reason == "target_package:identity_mismatch"
    assert guard.verify(None) == (False, "target_package:missing")
