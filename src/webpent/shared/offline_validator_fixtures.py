"""Offline evidence adapters for validator classes without live executors.

These adapters consume synthetic, already-collected evidence bundles only. They do
not send requests, execute probes, contact WAPTLab, or create findings. Their
purpose is to exercise causal/oracle/cleanup contracts locally while keeping live
validator reachability explicitly separate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from webpent.shared.campaigns import WAPTLAB_CAMPAIGNS
from webpent.shared.proof_oracles import OracleEngine, OracleFamily

_OFFLINE_KEYS: Final[frozenset[str]] = frozenset(
    {
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
)
_REQUIRED_BUNDLE_KEYS: Final[tuple[str, ...]] = (
    "campaign_key",
    "probe_id",
    "control_ref",
    "variant_ref",
    "oracle",
    "cleanup",
)


@dataclass(frozen=True)
class OfflineValidatorFixtureSpec:
    """A local-only evidence adapter specification."""

    campaign_key: str
    vuln_class: str
    adapter_id: str
    live_executor_available: bool = False
    network_allowed: bool = False


def build_offline_validator_fixture_registry() -> tuple[OfflineValidatorFixtureSpec, ...]:
    """Return stable adapters for all currently unsupported campaign classes."""
    specs: list[OfflineValidatorFixtureSpec] = []
    for campaign in WAPTLAB_CAMPAIGNS:
        key = str(campaign["key"])
        if key not in _OFFLINE_KEYS:
            continue
        vuln_class = str(campaign.get("validator") or key)
        specs.append(
            OfflineValidatorFixtureSpec(
                campaign_key=key,
                vuln_class=vuln_class,
                adapter_id=f"offline-fixture:{key}",
            )
        )
    # Mass-assignment has a detector but no standalone campaign entry. Keep its
    # evidence contract explicit and offline-only rather than manufacturing a
    # live campaign or treating the detector output as a confirmation.
    existing_keys = {spec.campaign_key for spec in specs}
    for key in (
        "mass_assignment",
        "request_smuggling",
        "cloud_storage_exposure",
        "subdomain_takeover",
        "jwt_key_confusion",
    ):
        if key in existing_keys:
            continue
        specs.insert(
            0,
            OfflineValidatorFixtureSpec(
                campaign_key=key,
                vuln_class=key,
                adapter_id=f"offline-fixture:{key}",
            ),
        )
    return tuple(specs)


def _oracle_family_for_campaign(campaign_key: str) -> OracleFamily | None:
    if campaign_key in {"download_idor", "tenant_context_switching"}:
        return OracleFamily.IDOR
    if campaign_key == "image_fetch_ssrf":
        return OracleFamily.SSRF
    if campaign_key in {"stored_profile_xss", "stored_message_xss"}:
        return OracleFamily.STORED_XSS
    if campaign_key in {"csv_ingestion_sqli", "csv_upload_sqli"}:
        return OracleFamily.CSV_SQLI
    if campaign_key == "request_smuggling":
        return OracleFamily.REQUEST_SMUGGLING
    if campaign_key == "cloud_storage_exposure":
        return OracleFamily.CLOUD_STORAGE_EXPOSURE
    if campaign_key == "subdomain_takeover":
        return OracleFamily.SUBDOMAIN_TAKEOVER
    if campaign_key == "jwt_key_confusion":
        return OracleFamily.JWT_KEY_CONFUSION
    return None


def _bundle_status(bundle: dict[str, Any]) -> str:
    missing = [key for key in _REQUIRED_BUNDLE_KEYS if key not in bundle]
    if missing:
        return "inconclusive"
    cleanup = bundle.get("cleanup")
    oracle = bundle.get("oracle")
    if not isinstance(cleanup, dict) or cleanup.get("status") != "completed":
        return "blocked"
    if not isinstance(oracle, dict):
        return "inconclusive"
    if oracle.get("negative_control_observed") is not True:
        return "inconclusive"
    if oracle.get("causal_signal") is not True:
        return "inconclusive"
    if oracle.get("evidence_complete") is not True:
        return "inconclusive"
    return "reviewable"


def evaluate_offline_fixture(bundle: dict[str, Any]) -> dict[str, Any]:
    """Classify a local evidence bundle without claiming a confirmed finding."""
    campaign_key = str(bundle.get("campaign_key") or "")
    known = {spec.campaign_key for spec in build_offline_validator_fixture_registry()}
    if campaign_key not in known:
        return {
            "campaign_key": campaign_key,
            "disposition": "inconclusive",
            "reason": "unsupported-offline-fixture",
            "finding_created": False,
            "network_used": False,
        }
    typed_observations = bundle.get("typed_observations")
    family = _oracle_family_for_campaign(campaign_key)
    typed_oracle = None
    if family is not None and isinstance(typed_observations, dict):
        typed_oracle = OracleEngine.evaluate(family, typed_observations)
        bundle = {**bundle, "oracle": typed_oracle.model_dump(mode="json")}
    status = _bundle_status(bundle)
    return {
        "campaign_key": campaign_key,
        "disposition": status,
        "reason": "offline-evidence-contract-only",
        "finding_created": False,
        "network_used": False,
        "cleanup_completed": status == "reviewable",
        "oracle_family": family.value if family is not None else None,
        "typed_oracle": typed_oracle.model_dump(mode="json") if typed_oracle else None,
    }


__all__ = [
    "OfflineValidatorFixtureSpec",
    "build_offline_validator_fixture_registry",
    "evaluate_offline_fixture",
]
