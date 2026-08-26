from webpent.benchmark.waptlab_offline_validator_fixtures import (
    build_waptlab_offline_validator_fixture_registry,
    evaluate_waptlab_offline_fixture,
)
from webpent.shared.offline_validator_fixtures import (
    build_offline_validator_fixture_registry,
)


def _complete_bundle(campaign_key: str) -> dict[str, object]:
    return {
        "campaign_key": campaign_key,
        "probe_id": "fixture-probe-01",
        "control_ref": "evidence:control",
        "variant_ref": "evidence:variant",
        "oracle": {
            "evidence_complete": True,
            "causal_signal": True,
            "negative_control_observed": True,
        },
        "cleanup": {"status": "completed"},
    }


def test_offline_registry_covers_exactly_current_missing_campaigns() -> None:
    specs = build_waptlab_offline_validator_fixture_registry()
    assert {spec.campaign_key for spec in specs} == {
        "mass_assignment",
        "request_smuggling",
        "cloud_storage_exposure",
        "subdomain_takeover",
        "jwt_key_confusion",
        "download_idor",
        "tenant_context_switching",
        "elasticsearch_snapshot_traversal",
        "public_backup_disclosure",
        "laravel_app_debug",
        "public_elasticsearch_exposure",
        "xslt_injection",
    }
    assert all(not spec.live_executor_available for spec in specs)
    assert all(not spec.network_allowed for spec in specs)


def test_shared_offline_registry_is_target_neutral_and_injectable() -> None:
    specs = build_offline_validator_fixture_registry(
        ({"key": "independent_fixture", "validator": "generic"},),
        offline_keys=frozenset({"independent_fixture"}),
    )
    assert [spec.campaign_key for spec in specs] == ["independent_fixture"]


def test_complete_offline_evidence_is_reviewable_not_a_finding() -> None:
    result = evaluate_waptlab_offline_fixture(_complete_bundle("mass_assignment"))
    assert result["disposition"] == "reviewable"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_incomplete_or_unclean_offline_evidence_cannot_be_reviewable() -> None:
    incomplete = _complete_bundle("xslt_injection")
    incomplete["oracle"] = {"evidence_complete": True}
    assert evaluate_waptlab_offline_fixture(incomplete)["disposition"] == "inconclusive"

    unclean = _complete_bundle("tenant_context_switching")
    unclean["cleanup"] = {"status": "pending"}
    assert evaluate_waptlab_offline_fixture(unclean)["disposition"] == "blocked"


def test_unknown_campaign_is_explicitly_inconclusive() -> None:
    result = evaluate_waptlab_offline_fixture(_complete_bundle("header_sqli"))
    assert result["disposition"] == "inconclusive"
    assert result["finding_created"] is False


def test_typed_request_smuggling_oracle_is_reviewable_only_with_controls() -> None:
    bundle = _complete_bundle("request_smuggling")
    bundle["typed_observations"] = {
        "parser_desync_observed": True,
        "smuggled_request_observed": True,
        "control_request_normalized": True,
    }
    result = evaluate_waptlab_offline_fixture(bundle)
    assert result["disposition"] == "reviewable"
    assert result["oracle_family"] == "request_smuggling"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_typed_cloud_storage_oracle_is_reviewable_only_with_controls() -> None:
    bundle = _complete_bundle("cloud_storage_exposure")
    bundle["typed_observations"] = {
        "unauthenticated_object_read": True,
        "sensitive_object_observed": True,
        "private_object_denied": True,
    }
    result = evaluate_waptlab_offline_fixture(bundle)
    assert result["disposition"] == "reviewable"
    assert result["oracle_family"] == "cloud_storage_exposure"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_typed_subdomain_takeover_oracle_is_reviewable_only_with_controls() -> None:
    bundle = _complete_bundle("subdomain_takeover")
    bundle["typed_observations"] = {
        "dangling_alias_observed": True,
        "service_claimable_observed": True,
        "owned_alias_not_claimable": True,
    }
    result = evaluate_waptlab_offline_fixture(bundle)
    assert result["disposition"] == "reviewable"
    assert result["oracle_family"] == "subdomain_takeover"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_typed_jwt_key_confusion_oracle_is_reviewable_only_with_controls() -> None:
    bundle = _complete_bundle("jwt_key_confusion")
    bundle["typed_observations"] = {
        "forged_token_accepted": True,
        "algorithm_substitution_observed": True,
        "control_token_rejected": True,
    }
    result = evaluate_waptlab_offline_fixture(bundle)
    assert result["disposition"] == "reviewable"
    assert result["oracle_family"] == "jwt_key_confusion"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_typed_idor_oracle_is_used_and_requires_negative_control() -> None:
    bundle = _complete_bundle("download_idor")
    bundle["typed_observations"] = {
        "owner_accessible": True,
        "foreign_accessible": True,
    }
    result = evaluate_waptlab_offline_fixture(bundle)
    assert result["disposition"] == "inconclusive"
    assert result["oracle_family"] == "idor"
    assert result["typed_oracle"]["negative_control_observed"] is False
