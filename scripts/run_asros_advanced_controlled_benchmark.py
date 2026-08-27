"""Build a redacted, offline ASROS multi-class controlled benchmark.

The runner consumes the already-recorded controlled local campaign artifact. It
never starts a target, sends a request, creates credentials, or promotes a
finding. Classes without an approved causal fixture remain blocked and are not
counted as false negatives or clean results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.benchmark.research_intelligence import (
    ResearchEvaluationCase,
    ResearchIntelligenceReport,
    evaluate_research_intelligence,
)

REQUIRED_CLASSES = (
    "idor",
    "privilege_escalation",
    "business_logic",
    "information_disclosure",
)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _recorded_idor_case(source: dict[str, Any]) -> ResearchEvaluationCase:
    evaluation = source.get("evaluation")
    if not isinstance(evaluation, dict) or not evaluation.get("cases"):
        raise ValueError("controlled campaign artifact has no evaluation case")
    recorded = evaluation["cases"][0]
    if not isinstance(recorded, dict):
        raise ValueError("controlled campaign evaluation case is invalid")
    if recorded.get("validation_outcome") != "confirmed":
        raise ValueError("controlled IDOR case is not confirmed in the recorded artifact")
    if not source.get("readiness", {}).get("preconditions_ready"):
        raise ValueError("controlled campaign readiness is not complete")
    if not source.get("case_result", {}).get("proof_bundle_ref"):
        raise ValueError("controlled campaign has no proof bundle reference")
    return ResearchEvaluationCase(
        case_id=str(recorded["case_id"]),
        target_id=str(recorded["target_id"]),
        vulnerability_class="idor",
        ground_truth_source="controlled_campaign_v1_recorded_artifact",
        hypothesis_generated=bool(recorded.get("hypothesis_generated")),
        rank=recorded.get("rank"),
        expected_rank=recorded.get("expected_rank"),
        information_gain=float(recorded.get("information_gain", 0.0)),
        evidence_quality=float(recorded.get("evidence_quality", 0.0)),
        validation_outcome="confirmed",
        ground_truth_outcome="confirmed",
        proof_complete=bool(recorded.get("proof_complete")),
        requests_used=int(recorded.get("requests_used", 0)),
        candidate_paths_considered=1,
        unnecessary_paths_executed=0,
    )


def _blocked_case(vulnerability_class: str) -> ResearchEvaluationCase:
    return ResearchEvaluationCase(
        case_id=f"asros-blocked-{vulnerability_class}-v1",
        target_id="controlled_local_idor_target_v1",
        vulnerability_class=vulnerability_class,
        ground_truth_source=None,
        validation_outcome="blocked",
        proof_complete=False,
        requests_used=0,
        candidate_paths_considered=1,
        unnecessary_paths_executed=0,
    )


def build_benchmark(source_path: Path) -> dict[str, Any]:
    source = _load_json(source_path)
    recorded_case = _recorded_idor_case(source)
    cases = [recorded_case]
    cases.extend(_blocked_case(name) for name in REQUIRED_CLASSES if name != "idor")
    report: ResearchIntelligenceReport = evaluate_research_intelligence(
        engagement_id="asros-advanced-controlled-benchmark-v1",
        cases=cases,
    )
    scorable = [case for case in cases if case.ground_truth_outcome is not None]
    return {
        "schema_version": "asros-advanced-controlled-benchmark-v1",
        "benchmark_scope": {
            "mode": "offline_replay_of_recorded_controlled_campaign",
            "target_id": "controlled_local_idor_target_v1",
            "network_scope": "loopback_only",
            "requests_sent_by_this_runner": 0,
            "persistent_service": False,
            "credentials": False,
            "state_mutation": False,
            "external_network": False,
        },
        "registered_vulnerability_classes": list(REQUIRED_CLASSES),
        "scorable_vulnerability_classes": sorted({case.vulnerability_class for case in scorable}),
        "blocked_vulnerability_classes": [name for name in REQUIRED_CLASSES if name != "idor"],
        "blocked_reason": (
            "No approved local causal fixture and candidate/control observations "
            "were available for these classes; they are excluded from TP/FN/clean scoring."
        ),
        "evaluation": report.model_dump(mode="json"),
        "governance": {
            "controlled_experiment": True,
            "real_world_detection_rate_measured": False,
            "qualification_effect": False,
            "official_isolated_p10_runs_authorized": False,
            "p10_status": "NOT_QUALIFIED",
            "p9_status": "NOT_QUALIFIED",
            "vip_status": "NOT_QUALIFIED",
            "bug_bounty_status": "BLOCKED",
            "human_signoff": False,
        },
        "provenance": {
            "source_artifact": source_path.name,
            "source_campaign_id": source.get("campaign_id"),
            "source_proof_bundle_ref_recorded": source.get("case_result", {}).get(
                "proof_bundle_ref"
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("reports/evaluation/arex/controlled_campaign_v1.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"),
    )
    args = parser.parse_args()
    result = build_benchmark(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["evaluation"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
