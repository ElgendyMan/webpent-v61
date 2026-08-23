from webpent.config.settings import ScanMode, Settings
from webpent.research.experiment_manager import ExperimentManager
from webpent.shared.action_authority import ActionAuthority, ActionRisk
from webpent.shared.campaign_executor import ActionExecutor, CampaignTask, CampaignTaskStatus


def _executor() -> ActionExecutor:
    settings = Settings(
        scan_mode=ScanMode.SAFE_SMART,
        smart_require_idempotency=True,
        smart_action_budget=10.0,
        smart_max_actions=5,
    )
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    return ActionExecutor(authority)


def _task(target_url: str = "http://example.test/object/1") -> CampaignTask:
    return CampaignTask(
        task_id="task-1",
        engagement_id="engagement-1",
        asset_id="asset-1",
        source_evidence_ids=("surface-1",),
        vulnerability_class="idor",
        hypothesis_id="hypothesis-1",
        target_url=target_url,
        idempotency_key="task-1-idempotent",
        expected_information_gain=0.8,
    )


def test_action_executor_seals_bundle_only_from_explicit_proof_payload():
    executor = _executor()
    record = executor.execute(
        _task(),
        lambda _task: {
            "finding_id": "finding-1",
            "proof_evidence": [{"status": 200, "object_id": "1"}],
            "evidence_refs": ["execution:1"],
            "negative_control": {"status": 403, "object_id": "1"},
        },
    )

    assert record["status"] == CampaignTaskStatus.EXECUTED.value
    assert record["proof_bundle_sealed"] is True
    assert record["negative_control_present"] is True
    assert record["proof_bundle"]["sealed"] is True
    assert record["proof_bundle"]["finding_id"] == "finding-1"


def test_action_executor_projects_experiment_lifecycle_without_promoting_finding():
    manager = ExperimentManager()
    settings = Settings(
        scan_mode=ScanMode.SAFE_SMART,
        smart_require_idempotency=True,
        smart_action_budget=10.0,
        smart_max_actions=5,
    )
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = ActionExecutor(authority, experiment_manager=manager)
    record = executor.execute(
        _task(),
        lambda _task: {
            "finding_id": "finding-1",
            "template_id": "idor",
            "proof_evidence": [{"status": 200}],
            "evidence_refs": ["execution:1"],
            "baseline": {"status": 403},
            "negative_control": {"status": 403},
            "causal_oracle": {"causal_signal": True},
            "target_backed": True,
            "negative_control_independent": True,
            "validator_id": "idor_differential",
            "validator_version": "1",
            "replay_metadata": {"replayable": True},
            "cleanup_status": "complete",
        },
    )

    assert record["proof_bundle_sealed"] is True
    assert record["experiment_record"]["template_id"] == "idor"
    assert record["experiment_record"]["proof_bundle_id"] == record["proof_bundle"]["bundle_id"]
    assert record["experiment_record"]["replayable"] is True
    assert manager.records()[0]["engagement_id"] == "engagement-1"
    assert record["proof_bundle"]["target_backed"] is True


def test_action_executor_denies_out_of_scope_without_calling_handler():
    executor = _executor()
    called = False

    def handler(_task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return {"proof_evidence": [{"unexpected": True}]}

    record = executor.execute(handler=handler, task=_task("http://other.test/object/1"))

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert called is False
    assert record["proof_bundle"] is None
    assert record["proof_bundle_sealed"] is False


def test_active_action_requires_authorization_and_approval():
    executor = _executor()
    task = _task()
    active_task = task.__class__(
        **{**task.__dict__, "method": "POST", "risk_tier": ActionRisk.ACTIVE}
    )

    record = executor.execute(active_task, lambda _task: {"proof_evidence": [{}]})

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert record["proof_bundle"] is None
