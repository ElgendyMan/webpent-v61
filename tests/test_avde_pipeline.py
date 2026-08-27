from __future__ import annotations

import pytest

from tests.test_avde import world
from webpent.avde import AVDEAdvisoryPipeline
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory


def test_pipeline_is_advisory_and_target_scoped() -> None:
    result = AVDEAdvisoryPipeline().run(
        world(),
        observations=({"asset": "record/1", "status": "deviation"},),
        attack_graph=({"steps": ["candidate", "control"], "required_capability": "analysis"},),
        available_capabilities=("analysis",),
    )
    assert result.engagement_id == "eng-1"
    assert result.target_id == "target-1"
    assert result.advisory_only is True
    assert result.creates_findings is False
    assert result.executes_transport is False
    assert result.overrides_policy is False
    assert len(result.hypotheses) == len(result.plans) == len(result.reviews)


def test_pipeline_writes_only_scoped_advisory_memory() -> None:
    memory = SecurityReasoningMemory(engagement_id="eng-1", target_id="target-1")
    result = AVDEAdvisoryPipeline().run(
        world(),
        attack_graph=({"steps": ["candidate"], "required_capability": "analysis"},),
        available_capabilities=("analysis",),
        memory=memory,
    )
    assert result.memory_record_ids
    assert memory.summary()["authoritative"] is False
    assert memory.summary()["execution_capability"] is False
    assert all(record.target_scope == "eng-1:target-1" for record in memory.records)
    with pytest.raises(ValueError, match="reasoning_memory_scope_mismatch"):
        AVDEAdvisoryPipeline().run(
            world(),
            memory=SecurityReasoningMemory(engagement_id="other", target_id="target-1"),
        )
