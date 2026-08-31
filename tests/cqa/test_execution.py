from __future__ import annotations

import pytest

from webpent.cqa import CandidateExecutionLayer, CaseExecutionSpec
from webpent.irta.v3 import build_independent_targets


@pytest.mark.asyncio
async def test_execution_produces_baseline_candidate_and_control_observations() -> None:
    target = build_independent_targets()[0]
    spec = CaseExecutionSpec(
        case_id="case-001",
        target_id=target.target_id,
        baseline_path=f"{target.base_path}/health",
        candidate_path=f"{target.base_path}/api/objects/alpha-1",
        negative_control_path=f"{target.base_path}/api/objects/missing",
    )
    record = await CandidateExecutionLayer(target).execute(spec)
    assert record.baseline_observation.status_code == 200
    assert record.candidate_observation.status_code in {200, 403, 404}
    assert record.negative_control_observation.status_code in {403, 404}
    assert len(record.candidate_observation.semantic_digest) == 64
    assert record.baseline_observation.request.header_names == (
        "X-Actor",
        "X-Tenant",
    )
    assert record.causal_result == "UNASSESSED"
    assert not record.scoring_eligible


def test_execution_rejects_mutating_methods_and_non_local_paths() -> None:
    target = build_independent_targets()[0]
    with pytest.raises(ValueError, match="only GET"):
        CaseExecutionSpec(
            "case-002",
            target.target_id,
            "/a",
            "/b",
            "/c",
            method="POST",
        )
    with pytest.raises(ValueError, match="local absolute"):
        CaseExecutionSpec("case-003", target.target_id, "https://x", "/b", "/c")


@pytest.mark.asyncio
async def test_execution_does_not_store_raw_request_headers_or_body() -> None:
    target = build_independent_targets()[0]
    spec = CaseExecutionSpec(
        "case-004",
        target.target_id,
        f"{target.base_path}/health",
        f"{target.base_path}/api/objects/alpha-1",
        f"{target.base_path}/api/objects/missing",
    )
    record = await CandidateExecutionLayer(target).execute(spec)
    assert "user-1" not in repr(record)
    assert "blue" not in repr(record)
    assert record.proof_bundle is None
    assert record.replay_result == "NOT_RUN"
