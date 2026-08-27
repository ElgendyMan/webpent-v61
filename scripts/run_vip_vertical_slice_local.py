"""Run the bounded local VIP Autonomous Vertical Slice v1.

This runner deliberately executes only a local fixture campaign and a passive
Juice Shop loopback campaign. It never uses credentials, payloads, mutations,
external destinations, or official qualification state.
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
    TargetSpec,
    VIPAutonomousVerticalSlice,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "reports/evaluation/vip_vertical_slice/VIP-AUTONOMOUS-VERTICAL-SLICE-LOCAL-E2E-v1.json"
)


def _target(target_id: str, scope: tuple[str, ...]) -> TargetSpec:
    return TargetSpec(
        target_id=target_id,
        canonical_origin="http://127.0.0.1:3000",
        scope=scope,
        method_policy=("GET",),
        request_budget=8,
        redirect_policy="same_origin_only",
        expires_at=(datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        authorization_ref="owner-authorized-local-loopback-vip-slice-v1",
    )


def _contract(case_id: str, *, target_local: bool) -> CaseContract:
    return CaseContract(
        case_id=case_id,
        vulnerability_class="local_vip_vertical_slice_contract",
        capability="http_read",
        path="/fixture" if target_local else "/",
        causal_predicate="candidate_matches_controlled_fixture"
        if target_local
        else "live_loopback_root_is_not_a_causal_finding",
        safe_preconditions=("local_fixture_or_loopback_ready",),
        negative_control_contract="independent_control_passed",
        target_local=target_local,
    )


def _authority() -> ActionAuthority:
    return ActionAuthority(
        allowed_origin="http://127.0.0.1:3000",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )


def _fixture_campaign() -> dict[str, Any]:
    state = {"causal_contract_ready": False}

    def handler(task: Any) -> dict[str, Any]:
        phase = task.workflow_state
        if phase == "baseline":
            match = False
            reason = "baseline_fixture_observation"
        elif phase == "negative_control":
            match = False
            reason = "independent_control_passed"
        else:
            match = state["causal_contract_ready"]
            reason = task.metadata["causal_predicate"]
        return {
            "observation": {
                "handler_status": "completed",
                "observation_role": phase,
                "semantic_reason": reason,
                "semantic_match": match,
                "semantic_oracle_ready": True,
                "target_backed": True,
                "replayable": True,
            }
        }

    def safe_change(payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("change_class") != "target_local":
            return {"regression_passed": False, "changed": False}
        state["causal_contract_ready"] = True
        return {
            "regression_passed": True,
            "changed": True,
            "change_scope": "local_fixture_metadata_only",
            "rollback": "discard_campaign_artifact",
        }

    target = _target("vip-local-fixture", ("/fixture",))
    slice_ = VIPAutonomousVerticalSlice(
        authority=_authority(),
        executor=CampaignExecutor(_authority()),
        capability_provider=lambda _target: {"http_read": {"available": True}},
        readiness_provider=lambda _target: {
            "ready": True,
            "external_contact": False,
            "mutation": False,
        },
        observation_handler=handler,
        safe_change_handler=safe_change,
    )
    return slice_.run(
        target=target,
        engagement_id="vip-local-fixture-e2e-v1",
        contracts=[_contract("local-fixture-causal-case", target_local=True)],
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


def _loopback_get(path: str) -> tuple[int | None, str, str]:
    parsed = urlsplit("http://127.0.0.1:3000" + path)
    if parsed.hostname != "127.0.0.1" or parsed.port != 3000:
        return None, "", "loopback_validation_failed"
    connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=3)
    try:
        connection.request("GET", parsed.path or "/")
        response = connection.getresponse()
        status = int(response.status)
        content_type = _content_type_family(response.getheader("Content-Type", ""))
        response.close()
        return status, content_type, "completed"
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return None, "", type(exc).__name__
    finally:
        connection.close()


def _juice_shop_campaign() -> dict[str, Any]:
    def handler(task: Any) -> dict[str, Any]:
        path = (
            "/__vip_vertical_slice_negative_control__"
            if task.workflow_state == "negative_control"
            else "/"
        )
        status, content_type, transport_status = _loopback_get(path)
        is_live = status is not None
        is_negative = task.workflow_state == "negative_control"
        return {
            "observation": {
                "handler_status": transport_status,
                "observation_role": task.workflow_state,
                "status_code": status if status is not None else 0,
                "content_type_family": content_type,
                "semantic_reason": "independent_control_passed"
                if is_negative
                else "live_loopback_root_is_not_a_causal_finding",
                "semantic_match": False,
                "semantic_oracle_ready": is_live,
                "target_backed": is_live,
                "replayable": is_live,
            }
        }

    target = _target("juice-shop-loopback", ("/",))
    authority = _authority()
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
    return slice_.run(
        target=target,
        engagement_id="juice-shop-loopback-passive-e2e-v1",
        contracts=[_contract("juice-shop-live-observation-only", target_local=False)],
    )


def main() -> int:
    fixture = _fixture_campaign()
    juice_shop = _juice_shop_campaign()
    artifact = {
        "schema": "vip-autonomous-vertical-slice-local-e2e-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "campaigns": {
            "local_fixture": fixture,
            "juice_shop_loopback_get_only": juice_shop,
        },
        "acceptance_checks": {
            "lifecycle_reported": all(
                campaign.get("lifecycle")
                for campaign in (fixture, juice_shop)
            ),
            "fixture_proof_sealed_verified_replayed": fixture["cases"][0]["proof"]
            == {
                **fixture["cases"][0]["proof"],
                "sealed": True,
                "verify_seal": True,
                "replay_status": "passed",
                "promotion_ready": True,
            },
            "fixture_before_after_completed": fixture["cases"][0]["improvement"]["retest"]["status"]
            == "completed",
            "juice_shop_is_observation_only": juice_shop["cases"][0]["status"]
            == "inconclusive",
            "no_raw_payloads_persisted": all(
                not case.get("raw_payloads_persisted", True)
                for campaign in (fixture, juice_shop)
                for case in campaign.get("cases", [])
            ),
            "no_external_contact": all(
                campaign["safety"]["external_contact"] is False
                for campaign in (fixture, juice_shop)
            ),
            "no_credentials": all(
                campaign["safety"]["credentials_used"] is False
                for campaign in (fixture, juice_shop)
            ),
            "no_state_mutation": all(
                campaign["safety"]["state_mutation"] is False
                for campaign in (fixture, juice_shop)
            ),
            "official_p10_gate_closed": all(
                campaign["safety"]["official_isolated_p10_runs_authorized"] is False
                for campaign in (fixture, juice_shop)
            ),
            "qualification_claim_absent": all(
                campaign["safety"]["qualification_claim"] is None
                for campaign in (fixture, juice_shop)
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
            "The fixture proof is a bounded regression artifact, not official P10 evidence.",
            "Juice Shop campaign is passive GET-only observation and remains non-scoring.",
            "No external target, credentials, payloads, mutation, or qualification "
            "action was attempted.",
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

# End of module
