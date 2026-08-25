import pytest

from webpent.benchmark.juice_shop_safe_cases import (
    JUICE_SHOP_SAFE_CASES,
    JuiceShopSafeCase,
    get_juice_shop_safe_case,
    safe_case_categories,
    safe_case_ids,
)


def test_safe_registry_has_unique_ids_and_six_categories() -> None:
    assert len(safe_case_ids()) == len(set(safe_case_ids()))
    assert len(JUICE_SHOP_SAFE_CASES) >= 10
    assert len(safe_case_categories()) >= 6
    assert all(case.safe_to_execute for case in JUICE_SHOP_SAFE_CASES)
    assert all(
        case.mapping_status == "pending_independent_review"
        for case in JUICE_SHOP_SAFE_CASES
    )
    assert all(
        case.oracle_status == "pending_safe_oracle_review"
        for case in JUICE_SHOP_SAFE_CASES
    )


def test_registry_cases_are_relative_and_payload_free() -> None:
    for case in JUICE_SHOP_SAFE_CASES:
        assert case.path.startswith("/")
        if case.operation == "navigate":
            assert "#" not in case.path
        assert "password" not in case.path.lower()
        assert "token" not in case.path.lower()
        assert "javascript:" not in case.path.lower()


def test_exact_lookup_fails_closed() -> None:
    assert get_juice_shop_safe_case("juice.local_xss.v1").operation == "typed_search"
    with pytest.raises(KeyError, match="unknown_juice_shop_safe_case"):
        get_juice_shop_safe_case("juice.unknown.v1")


def test_invalid_absolute_or_fragment_path_is_rejected() -> None:
    with pytest.raises(ValueError, match="relative"):
        JuiceShopSafeCase(
            case_id="juice.invalid.absolute",
            challenge_key="x",
            category="XSS",
            path="https://example.invalid/",
            operation="navigate",
            oracle_id="http.read_only.status_and_shape",
            source_ref="source",
        )
    with pytest.raises(ValueError, match="fragment"):
        JuiceShopSafeCase(
            case_id="juice.invalid.fragment",
            challenge_key="x",
            category="XSS",
            path="/#/search",
            operation="navigate",
            oracle_id="http.read_only.status_and_shape",
            source_ref="source",
        )
