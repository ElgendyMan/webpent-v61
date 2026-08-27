from __future__ import annotations

import hashlib

import pytest

from webpent.research_engine.campaign_state import CampaignState


def _state(target: str = "controlled-local") -> CampaignState:
    return CampaignState(
        campaign_id="campaign-arex-001",
        target_identity=target,
        scope_digest=hashlib.sha256(target.encode()).hexdigest(),
        current_objectives=("map-attack-surface", "validate-id-or-access"),
        time_budget=120,
    )


def test_snapshot_restore_is_deterministic_and_redacted() -> None:
    state = _state()
    snapshot = state.snapshot()
    restored = CampaignState.restore(snapshot)

    assert restored == state
    assert restored.snapshot() == snapshot
    assert restored.snapshot_digest() == state.snapshot_digest()
    assert "authorization" not in snapshot.lower()
    assert "body" not in snapshot.lower()


def test_evolve_links_parent_and_marks_task() -> None:
    state = _state()
    next_state = state.mark_task("task-1", "completed")

    assert next_state.completed_tasks == ("task-1",)
    assert next_state.lineage.sequence == 1
    assert next_state.lineage.parent_snapshot_digest == state.snapshot_digest()
    assert next_state.lineage.event_id == "task:completed:task-1"


def test_task_status_buckets_are_disjoint() -> None:
    payload = _state().model_dump(mode="json")
    payload.update({"completed_tasks": ["same"], "blocked_tasks": ["same"]})
    with pytest.raises(ValueError, match="campaign_task_status_overlap"):
        CampaignState.model_validate(payload)


def test_restore_rejects_bad_schema_and_secret_like_fields() -> None:
    with pytest.raises(ValueError, match="unsupported_campaign_snapshot_schema"):
        CampaignState.restore('{"schema_version": 99}')

    with pytest.raises(ValueError, match="unsafe_campaign_field"):
        CampaignState.restore('{"schema_version": 1, "authorization": "redacted"}')


def test_scope_is_part_of_state_and_cannot_be_empty() -> None:
    first = _state("target-a")
    second = _state("target-b")

    assert first.target_identity != second.target_identity
    assert first.scope_digest != second.scope_digest
    assert first.snapshot_digest() != second.snapshot_digest()


def test_unknown_fields_fail_closed() -> None:
    with pytest.raises(ValueError):
        CampaignState.model_validate(
            {
                "campaign_id": "c",
                "target_identity": "t",
                "scope_digest": "0" * 64,
                "unexpected": "value",
            }
        )
