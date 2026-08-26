from webpent.shared.campaigns import build_waptlab_campaign_ledger
from webpent.shared.validator_plugins import (
    build_waptlab_validator_plugin_registry,
    plugin_capability_gaps,
)


def _entries_by_key(ledger):
    return {entry["key"]: entry for entry in ledger["entries"]}


def test_vertical_campaigns_reuse_registered_deterministic_validators():
    ledger = build_waptlab_campaign_ledger()
    entries = _entries_by_key(ledger)

    for key, validator in {
        "download_idor": "idor",
        "tenant_context_switching": "idor",
        "public_backup_disclosure": "info_disclosure",
        "laravel_app_debug": "info_disclosure",
        "public_elasticsearch_exposure": "info_disclosure",
    }.items():
        assert entries[key]["validator"] == validator
        assert entries[key]["validator_id"] == validator
        assert entries[key]["status"] == "not_observed"
        assert entries[key]["human_review_only"] is False
        assert entries[key]["evidence_complete"] is False


def test_only_unsupported_vertical_campaigns_remain_missing_validator():
    ledger = build_waptlab_campaign_ledger()
    assert ledger["summary"] == {"not_observed": 18, "missing-validator": 2}
    entries = _entries_by_key(ledger)
    assert entries["elasticsearch_snapshot_traversal"]["status"] == "missing-validator"
    assert entries["xslt_injection"]["status"] == "missing-validator"


def test_observed_vertical_campaign_is_tested_not_confirmed():
    ledger = build_waptlab_campaign_ledger(observed_campaigns={"download_idor"})
    entry = _entries_by_key(ledger)["download_idor"]
    assert entry["status"] == "tested"
    assert entry["evidence_complete"] is True
    assert entry["human_review_only"] is False


def test_plugin_registry_exposes_base_validator_for_vertical_campaigns():
    plugins = {
        plugin.campaign_key: plugin
        for plugin in build_waptlab_validator_plugin_registry()
    }
    assert plugins["download_idor"].validator_id == "idor"
    assert plugins["tenant_context_switching"].validator_id == "idor"
    assert plugins["public_backup_disclosure"].validator_id == "info_disclosure"
    assert plugins["laravel_app_debug"].validator_id == "info_disclosure"
    assert plugins["public_elasticsearch_exposure"].validator_id == "info_disclosure"

    gaps = plugin_capability_gaps(tuple(plugins.values()))
    assert {gap["plugin_id"] for gap in gaps} == {
        "campaign:elasticsearch_snapshot_traversal",
        "campaign:xslt_injection",
    }
