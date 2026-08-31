from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from webpent.cqa import CandidateExecutionLayer, CaseExecutionSpec, ExecutionRecord
from webpent.irta.v3 import build_independent_targets

OUTPUT = Path("reports/cqa_v1/campaign_observations.json")


def case_spec(target_id: str, base_path: str, index: int) -> CaseExecutionSpec:
    object_id = f"{target_id.removeprefix('target-')}-{(index % 4) + 1}"
    candidate = (
        f"{base_path}/api/objects/{object_id}"
        if index % 2 == 0
        else f"{base_path}/api/profile"
    )
    return CaseExecutionSpec(
        case_id=f"{target_id}-case-{index + 1:02d}",
        target_id=target_id,
        baseline_path=f"{base_path}/health",
        candidate_path=candidate,
        negative_control_path=f"{base_path}/api/objects/missing",
    )


def serialize(record: ExecutionRecord) -> dict[str, object]:
    return asdict(record)


async def main() -> None:
    records: list[dict[str, object]] = []
    for target in build_independent_targets():
        layer = CandidateExecutionLayer(target)
        for index in range(10):
            record = await layer.execute(case_spec(target.target_id, target.base_path, index))
            records.append(serialize(record))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(records, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"targets": 5, "cases": len(records), "scoring_eligible": 0}))


if __name__ == "__main__":
    asyncio.run(main())
