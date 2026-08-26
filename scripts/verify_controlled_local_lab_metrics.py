"""Recompute controlled local-lab metrics from persisted redacted artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.benchmark.p10 import P10GroundTruth, P10Run, evaluate_p10

_CATEGORY_BY_KEY = {
    "directory_listing": "Sensitive Data Exposure",
    "backup_resource": "Sensitive Data Exposure",
    "typed_search_sink": "XSS",
    "verbose_error_shape": "Security Misconfiguration",
    "log_record_shape": "Observability Failures",
    "signature_shape": "Observability Failures",
    "metrics_shape": "Observability Failures",
    "policy_shape": "Miscellaneous",
    "scoreboard_shape": "Miscellaneous",
    "privacy_surface": "Security through Obscurity",
}


def _case_contracts(packet: dict[str, Any]) -> list[P10GroundTruth]:
    return [
        P10GroundTruth(
            case_id=str(case["case_id"]),
            category=_CATEGORY_BY_KEY[str(case["semantic_key"])],
            expected=True,
            mapping_status="approved",
            oracle_status="ready",
        )
        for case in packet["case_contracts"]
    ]


def _runs(payload: dict[str, Any]) -> list[P10Run]:
    result: list[P10Run] = []
    for run in payload["runs"]:
        ids = frozenset(case["case_id"] for case in run["cases"])
        result.append(
            P10Run(
                run_id=run["run_id"],
                workspace_id=run["workspace_id"],
                artifact_namespace=run["artifact_namespace"],
                target_ref=payload["lab"]["target_ref"],
                candidate_case_ids=ids,
                executed_case_ids=ids,
                proof_case_ids=ids,
                replay_case_ids=ids,
                target_unchanged=payload["lab"]["target_modified"] is False,
                findings_are_live=True,
            )
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.artifact.read_text(encoding="utf-8"))
    packet = json.loads(args.packet.read_text(encoding="utf-8"))
    recomputed = evaluate_p10(_case_contracts(packet), _runs(payload))
    if recomputed != payload["p10_projection"]:
        raise RuntimeError("persisted_metrics_do_not_match_recomputed_metrics")
    result = {
        "schema_version": "controlled-local-lab-metrics-verification.v1",
        "metrics_match": True,
        "p10_projection": recomputed,
        "official_p10_qualification": "NOT_QUALIFIED",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
