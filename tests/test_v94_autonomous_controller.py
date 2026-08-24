from __future__ import annotations

from types import SimpleNamespace

from webpent.shared.action_authority import ActionAuthority
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import ActionExecutor


def _state() -> dict:
    return {
        "smart_mode": True,
        "scan_mode": "safe-smart",
        "engagement_id": "engagement:test-controller",
        "target": {"url": "http://example.test"},
        "campaign_plan": {
            "entries": [
                {
                    "key": "sqli",
                    "matched_observation_refs": ["surface:0"],
                    "contract": {
                        "method": "GET",
                        "oracle": "status_compare",
                        "preconditions": ["surface observed"],
                        "observed_preconditions": ["surface observed"],
                    },
                }
            ]
        },
        "crawled_data": {
            "surface_records": [
                {"url": "http://example.test/item", "ref": "surface:0"}
            ]
        },
        "findings": [],
        "hypotheses": [],
        "campaign_task_outcomes": [],
        "research_decision_trace": [],
    }


def test_controller_requires_injected_runtime_dependencies() -> None:
    try:
        AutonomousController().run(_state())
    except RuntimeError as exc:
        assert "runtime_dependencies_required" in str(exc)
    else:
        raise AssertionError("controller must reject missing runtime dependencies")


def test_controller_executes_only_through_action_executor() -> None:
    authority = ActionAuthority(
        settings=SimpleNamespace(
            scan_mode="safe-smart",
            smart_auto_approve=False,
            smart_action_budget=10.0,
            smart_max_actions=3,
            smart_require_idempotency=True,
        ),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = ActionExecutor(authority)
    calls: list[str] = []

    def handler(task):
        calls.append(task.task_id)
        from webpent.models.findings import Finding, Severity, VulnClass
        from webpent.shared.verifier import _target_fingerprint, verify_replay_evidence

        finding = Finding(
            title="Controller proof fixture",
            severity=Severity.HIGH,
            description="target-backed controller fixture",
            tool_name="test.controller",
            url=task.target_url,
            vuln_class=VulnClass.IDOR,
        )
        fingerprint = _target_fingerprint(task.target_url)

        def observation(role: str, marker: str) -> dict[str, object]:
            return {
                "target_backed": True,
                "observation_role": role,
                "target_fingerprint": fingerprint,
                "request_digest": f"sha256:{marker * 64}",
                "response_digest": f"sha256:{marker * 64}",
                "status_code": 200 if role == "candidate" else 404,
                "replayable": True,
            }

        result = verify_replay_evidence(
            finding,
            baseline=observation("baseline", "a"),
            candidate=observation("candidate", "b"),
            negative_control=observation("negative_control", "c"),
            causal_signal=True,
            negative_control_complete=True,
            validator_id="test.controller",
            validator_version="1.0",
            causal_basis="target-backed controller differential",
            engagement_id=task.engagement_id,
            hypothesis_id=task.hypothesis_id,
            scope_context={"allowed_origin": "http://example.test"},
            identity_context={"mode": "anonymous"},
            require_target_backed=True,
        )
        assert result.passed is True
        return result.evidence

    result = AutonomousController(action_executor=executor, max_iterations=2).run(
        _state(), handler=handler, iterations=1
    )

    assert len(calls) == 1
    assert result["smart_replanning"]["status"] == "controller_completed"
    assert result["campaign_task_outcomes"][0]["status"] == "executed"
    assert result["campaign_task_outcomes"][0]["proof_bundle_sealed"] is True
    assert result["lifecycle_events"]


def test_controller_blocks_unproven_preconditions_before_handler() -> None:
    state = _state()
    state["campaign_plan"]["entries"][0]["contract"].pop("observed_preconditions", None)
    calls: list[str] = []

    result = AutonomousController(
        action_executor=ActionExecutor(
            ActionAuthority(
                settings=SimpleNamespace(
                    scan_mode="safe-smart",
                    smart_auto_approve=False,
                    smart_action_budget=10.0,
                    smart_max_actions=3,
                    smart_require_idempotency=True,
                ),
                allowed_origin="http://example.test",
                manifest={"capabilities": {"http_read": {"available": True}}},
            )
        )
    ).run(state, handler=lambda task: calls.append(task.task_id), iterations=1)

    assert calls == []
    assert result["campaign_task_outcomes"][0]["status"] == "blocked_by_precondition"
    assert result["smart_replanning"]["controller_executed"] == 0


def test_controller_requires_executor_when_handler_is_present() -> None:
    calls: list[str] = []

    try:
        AutonomousController().run(_state(), handler=lambda task: calls.append(task.task_id))
    except RuntimeError as exc:
        assert "runtime_dependencies_required" in str(exc)
    else:
        raise AssertionError("controller must reject a missing ActionExecutor")
    assert calls == []
