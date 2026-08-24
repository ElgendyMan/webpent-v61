from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.config.settings import ScanMode, Settings
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.browser_proof_runner import (
    BrowserProofRunner,
    EphemeralProbe,
)
from webpent.shared.campaign_executor import ActionExecutor
from webpent.shared.control_plane import compile_scope
from webpent.shared.control_plane_runtime import BrowserActionAdapter
from webpent.shared.control_plane_spine import build_control_plane_runtime
from webpent.shared.g02_contract import G02_HTTP_APPROVAL_EXPIRY
from webpent.shared.runtime import (
    CONTROL_PLANE_BROWSER_INVENTORY_REF,
    CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
    AdapterRegistry,
    RegisteredAdapter,
)

ENGAGEMENT = "runner-local-engagement"
ORIGIN = "https://app.example.test"
TARGET_URL = f"{ORIGIN}/search"


def _finding() -> Finding:
    return Finding(
        title="Target-backed browser observation",
        severity=Severity.HIGH,
        description="Runner fixture finding.",
        tool_name="fixture.browser",
        url=TARGET_URL,
        vuln_class=VulnClass.XSS,
    )


def _scope():
    return compile_scope(
        engagement_id=ENGAGEMENT,
        root_domains=(ORIGIN,),
        created_by="runner-test",
        approval_source="offline-fixture",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_schemes=("https",),
        allowed_ports=(443,),
        path_rules=("/",),
    )


def _settings() -> Settings:
    return Settings(
        scan_mode=ScanMode.SAFE_SMART,
        smart_require_idempotency=True,
        smart_action_budget=20.0,
        smart_max_actions=10,
    )


def _build_runner(
    tmp_path: Path,
    *,
    missing_observation: bool = False,
) -> tuple[BrowserProofRunner, list[dict[str, Any]]]:
    probes: dict[str, str] = {}
    seen: list[dict[str, Any]] = []

    def handler(request) -> dict[str, Any]:
        seen.append(request.model_dump(mode="json"))
        if missing_observation:
            return {"handler_status": "completed"}
        role = request.observation_role
        stable = role in {"baseline", "negative_control"}
        marker = "a" if stable else "c"
        return {
            "handler_status": "completed",
            "target_backed": True,
            "observation_role": role,
            "target_fingerprint": "sha256:" + hashlib.sha256(
                b"https://app.example.test/search"
            ).hexdigest(),
            "request_digest": request.probe_digest,
            "response_digest": f"sha256:{marker * 64}",
            "status_code": 200,
            "network_event_count": 1 if stable else 2,
            "dom_digest": f"sha256:{marker * 64}",
            "replayable": True,
        }

    adapter = BrowserActionAdapter(
        handler,
        probe_registrar=probes.__setitem__,
        probe_cleaner=probes.pop,
    )
    registry = AdapterRegistry()
    registry.register(
        RegisteredAdapter(
            name="control_plane_browser",
            capability="browser_action",
            transport="injected-browser",
            handler=lambda _request: {"registered": True},
            source="runner-test",
            version="1",
            policy_checked=True,
            canonical_wrapper="control_plane.browser_action",
            scope_policy="engagement_scope_same_origin",
            static_inventory_ref=CONTROL_PLANE_BROWSER_INVENTORY_REF,
            proof_contract=CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
            expires_at=G02_HTTP_APPROVAL_EXPIRY,
        )
    )
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin=ORIGIN,
        manifest={"capabilities": {"browser_action": {"available": True}}},
        adapter_registry=registry,
        require_g02=True,
    )
    executor = ActionExecutor(authority)
    control_plane = build_control_plane_runtime(
        engagement_id=ENGAGEMENT,
        scope=_scope(),
        executor=executor,
        profile_root=str(tmp_path / "profiles"),
    )
    session = control_plane.session_manager.create_session(
        engagement_id=ENGAGEMENT,
        profile_ref="runner-test",
        cookie_fingerprint="sha256:" + "1" * 64,
    )
    runner = BrowserProofRunner(
        replay_engine=control_plane.replay_engine,
        adapter=adapter,
        session=session,
        scope=control_plane.scope,
        engagement_id=ENGAGEMENT,
    )
    return runner, seen


def _predicate(baseline, candidate, negative_control):
    return (
        baseline["response_digest"] != candidate["response_digest"]
        and baseline["response_digest"] == negative_control["response_digest"]
        and baseline["network_event_count"] == negative_control["network_event_count"],
        "target_response_and_network_differential",
    )


def _probes():
    return (
        EphemeralProbe.from_value("baseline", "baseline-value"),
        EphemeralProbe.from_value("candidate", "candidate-value"),
        EphemeralProbe.from_value("negative_control", "negative-value"),
    )


def test_runner_executes_three_typed_replays_without_raw_probe_transport(tmp_path):
    runner, seen = _build_runner(tmp_path)
    baseline, candidate, negative = _probes()

    result = runner.run(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=negative,
        causal_predicate=_predicate,
        scope_context={"target_origin": ORIGIN, "scope_bound": True},
        identity_context={"mode": "anonymous", "session_ref": runner.session.session_id},
        target_url=TARGET_URL,
        probe_values={
            baseline.probe_ref: "baseline-value",
            candidate.probe_ref: "candidate-value",
            negative.probe_ref: "negative-value",
        },
    )

    assert result.passed is True
    assert result.attestation is not None
    assert len(seen) == 3
    assert {item["observation_role"] for item in seen} == {
        "baseline",
        "candidate",
        "negative_control",
    }
    assert all("candidate-value" not in item.values() for item in seen)


def test_runner_fails_closed_when_observation_is_missing(tmp_path):
    runner, seen = _build_runner(tmp_path, missing_observation=True)
    baseline, candidate, negative = _probes()

    result = runner.run(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=negative,
        causal_predicate=_predicate,
        scope_context={"target_origin": ORIGIN, "scope_bound": True},
        identity_context={"mode": "anonymous", "session_ref": runner.session.session_id},
        target_url=TARGET_URL,
        probe_values={
            baseline.probe_ref: "baseline-value",
            candidate.probe_ref: "candidate-value",
            negative.probe_ref: "negative-value",
        },
    )

    assert result.passed is False
    assert result.attestation is None
    assert result.reason == "baseline_observation_missing_or_unusable"
    assert len(seen) == 3


def test_runner_rejects_identical_candidate_and_negative_probe_digest(tmp_path):
    runner, seen = _build_runner(tmp_path)
    baseline = EphemeralProbe.from_value("baseline", "baseline-value")
    candidate = EphemeralProbe.from_value("candidate", "same-value")
    negative = EphemeralProbe.from_value("negative_control", "same-value")

    result = runner.run(
        _finding(),
        baseline=baseline,
        candidate=candidate,
        negative_control=negative,
        causal_predicate=_predicate,
        scope_context={"target_origin": ORIGIN, "scope_bound": True},
        identity_context={"mode": "anonymous", "session_ref": runner.session.session_id},
        target_url=TARGET_URL,
        probe_values={
            baseline.probe_ref: "baseline-value",
            candidate.probe_ref: "same-value",
            negative.probe_ref: "same-value",
        },
    )

    assert result.passed is False
    assert result.reason == "negative_control_probe_must_be_distinct"
    assert seen == []
