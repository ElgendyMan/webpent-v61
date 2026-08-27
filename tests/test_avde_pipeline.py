from __future__ import annotations

from tests.test_avde import world
from webpent.avde import AVDEAdvisoryPipeline


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
