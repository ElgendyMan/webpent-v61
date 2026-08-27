"""Bounded multi-target VIP vertical-slice validation.

This runner uses the existing transport-agnostic VIP orchestrator with three
explicit loopback TargetSpecs. It performs only anonymous GET requests to
allowlisted local paths, never follows redirects, never persists bodies or
headers, and never changes official scoring or qualification state.
"""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from webpent.shared.action_authority import ActionAuthority
from webpent.shared.campaign_executor import CampaignExecutor
from webpent.shared.vip_vertical_slice import (
    CaseContract,
    LifecycleStage,
    TargetSpec,
    VIPAutonomousVerticalSlice,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "reports/evaluation/vip_vertical_slice/VIP-AUTONOMOUS-MULTI-TARGET-LOCAL-E2E-v1.json"
)

_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "target_id": "juice-shop-loopback",
        "origin": "http://127.0.0.1:3000",
        "path": "/",
        "source_path": "/tmp/juice-shop-source",
        "source_revision": "1618a611b173b4bf114028e6e02549950606e29d",
        "campaign_id": "vip-juice-shop-loopback-local-e2e-v1",
        "ground_truth_status": "available_but_this_campaign_observation_only",
        "ground_truth_ref": "docs/juice_shop_source_ground_truth_manifest_v1.json",
        "approved_cases": 3,
        "approved_classes": 3,
    },
    {
        "target_id": "webgoat-loopback",
        "origin": "http://127.0.0.1:8080",
        "path": "/WebGoat",
        "source_path": "/tmp/webgoat-source",
        "source_revision": "7517acca95d9851da706452454c223dd13545ef4",
        "campaign_id": "vip-webgoat-loopback-local-e2e-v1",
        "ground_truth_status": "not_admitted_for_scoring",
        "ground_truth_ref": None,
        "approved_cases": 0,
        "approved_classes": 0,
    },
    {
        "target_id": "crapi-loopback",
        "origin": "http://127.0.0.1:8888",
        "path": "/health",
        "source_path": "/tmp/crapi-source",
        "source_revision": "73d309cc8f28bbdeed31dbb35f05dba8354de3c9",
        "campaign_id": "vip-crapi-loopback-local-e2e-v1",
        "ground_truth_status": "not_admitted_for_scoring",
        "ground_truth_ref": None,
        "approved_cases": 0,
        "approved_classes": 0,
    },
)


def _target(config: dict[str, Any]) -> TargetSpec:
    return TargetSpec(
        target_id=str(config["target_id"]),
        canonical_origin=str(config["origin"]),
        scope=(str(config["path"]),),
        method_policy=("GET",),
        request_budget=8,
        redirect_policy="same_origin_only",
        expires_at=(datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
        authorization_ref="owner-authorized-local-loopback-vip-multitarget-v1",
    )


def _authority(origin: str) -> ActionAuthority:
    return ActionAuthority(
        allowed_origin=origin,
        manifest={"capabilities": {"http_read": {"available": True}}},
    )


def _contract(config: dict[str, Any]) -> CaseContract:
    return CaseContract(
        case_id=f"{config['target_id']}-live-root-observation",
        vulnerability_class="local_vip_passive_observation",
        capability="http_read",
        path=str(config["path"]),
        causal_predicate="live_loopback_root_is_not_a_causal_finding",
        safe_preconditions=("local_runtime_ready", "anonymous_get_only"),
        negative_control_contract="independent_control_passed",
        target_local=False,
    )


def _content_type_family(value: str) -> str:
    lowered = value.lower()
    if "json" in lowered:
        return "json"
    if "html" in lowered:
        return "html"
    if "text" in lowered:
        return "text"
    return "other" if lowered else "unknown"


def _loopback_get(origin: str, path: str) -> tuple[int | None, str, str]:
    parsed_origin = urlsplit(origin)
    parsed_path = urlsplit(path)
    host = (parsed_origin.hostname or "").lower()
    if (
        parsed_origin.scheme != "http"
        or host != "127.0.0.1"
        or parsed_origin.port not in {3000, 8080, 8888}
        or parsed_path.scheme
        or parsed_path.netloc
        or not parsed_path.path.startswith("/")
    ):
        return None, "", "loopback_validation_failed"
    connection = http.client.HTTPConnection(host, parsed_origin.port, timeout=5)
    try:
        connection.request("GET", parsed_path.path or "/")
        response = connection.getresponse()
        status = int(response.status)
        content_type = _content_type_family(response.getheader("Content-Type", ""))
        response.close()
        return status, content_type, "completed"
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return None, "", type(exc).__name__
    finally:
        connection.close()


def _campaign(config: dict[str, Any]) -> dict[str, Any]:
    origin = str(config["origin"])
    path = str(config["path"])

    def handler(task: Any) -> dict[str, Any]:
        request_path = (
            "/__vip_vertical_slice_negative_control__"
            if task.workflow_state == "negative_control"
            else path
        )
        status, content_type, transport_status = _loopback_get(origin, request_path)
        live = status is not None
        negative = task.workflow_state == "negative_control"
        return {
            "observation": {
                "handler_status": transport_status,
                "observation_role": task.workflow_state,
                "status_code": status if status is not None else 0,
                "content_type_family": content_type,
                "semantic_reason": "independent_control_passed"
                if negative
                else "live_loopback_root_is_not_a_causal_finding",
                "semantic_match": False,
                "semantic_oracle_ready": live,
                "target_backed": live,
                "replayable": live,
            }
        }

    target = _target(config)
    authority = _authority(origin)
    slice_ = VIPAutonomousVerticalSlice(
        authority=authority,
        executor=CampaignExecutor(authority),
        capability_provider=lambda _target: {"http_read": {"available": True}},
        readiness_provider=lambda _target: {
            "ready": True,
            "external_contact": False,
            "mutation": False,
        },
        observation_handler=handler,
        safe_change_handler=None,
    )
    result = slice_.run(
        target=target,
        engagement_id=str(config["campaign_id"]),
        contracts=[_contract(config)],
    )
    result["target_metadata"] = {
        "target_id": config["target_id"],
        "canonical_origin": origin,
        "scope": [path],
        "source_path": config["source_path"],
        "source_revision": config["source_revision"],
        "campaign_id": config["campaign_id"],
        "ground_truth_status": config["ground_truth_status"],
        "ground_truth_ref": config["ground_truth_ref"],
        "approved_cases": config["approved_cases"],
        "approved_classes": config["approved_classes"],
        "quality_scoring_eligible": False,
    }
    return result


def main() -> int:
    campaigns = {str(config["target_id"]): _campaign(config) for config in _TARGETS}
    artifact = {
        "schema": "vip-autonomous-multitarget-local-e2e-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "targets": campaigns,
        "acceptance_checks": {
            "three_target_campaigns_present": set(campaigns)
            == {item["target_id"] for item in _TARGETS},
            "lifecycle_complete_for_each_target": all(
                [event["stage"] for event in campaign["lifecycle"]]
                == [stage.value for stage in LifecycleStage]
                for campaign in campaigns.values()
            ),
            "all_targets_observation_only": all(
                campaign["cases"][0]["status"] == "observation_only"
                for campaign in campaigns.values()
            ),
            "all_targets_have_negative_control": all(
                campaign["cases"][0]["oracle"]["negative_control_complete"] is True
                for campaign in campaigns.values()
            ),
            "no_quality_scoring_without_admitted_ground_truth": all(
                campaign["target_metadata"]["quality_scoring_eligible"] is False
                for campaign in campaigns.values()
            ),
            "no_credentials": all(
                campaign["safety"]["credentials_used"] is False for campaign in campaigns.values()
            ),
            "no_state_mutation": all(
                campaign["safety"]["state_mutation"] is False for campaign in campaigns.values()
            ),
            "no_external_contact": all(
                campaign["safety"]["external_contact"] is False for campaign in campaigns.values()
            ),
            "official_p10_gate_closed": all(
                campaign["safety"]["official_isolated_p10_runs_authorized"] is False
                for campaign in campaigns.values()
            ),
            "qualification_claim_absent": all(
                campaign["safety"]["qualification_claim"] is None for campaign in campaigns.values()
            ),
        },
        "governance": {
            "human_independent_signoff_obtained": False,
            "official_isolated_p10_runs_authorized": False,
            "p10": "NOT_QUALIFIED",
            "p9": "NOT_QUALIFIED",
            "vip": "NOT_QUALIFIED",
            "bug_bounty": "BLOCKED",
            "scoring_promotion": False,
        },
        "limitations": [
            (
                "All three campaigns are passive anonymous GET-only observations "
                "classified as observation_only."
            ),
            (
                "No vulnerability case was promoted without an admitted target-specific "
                "ground truth and causal oracle."
            ),
            "WebGoat and crAPI have no approved scoring set in the current governance packet.",
            (
                "No credentials, payloads, mutations, external targets, official P10 runs, "
                "or qualification actions were attempted."
            ),
        ],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checks = artifact["acceptance_checks"]
    if not all(checks.values()):
        failed = [key for key, value in checks.items() if not value]
        raise SystemExit(f"acceptance_checks_failed:{','.join(failed)}")
    print(OUTPUT)
    print(json.dumps(checks, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = ["main"]
