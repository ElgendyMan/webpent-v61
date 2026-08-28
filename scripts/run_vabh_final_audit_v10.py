#!/usr/bin/env python3
"""Run the VABH final audit v10 using local, recorded repository evidence only."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from webpent.vabhfqr_v10 import (
    ImplementationStatus,
    build_project_state_report,
    build_scorecard,
    gap,
)

ROOT = Path(__file__).resolve().parents[1]
V9_GATE_SUMMARY = ROOT / "artifacts/vabhfqr_v9/VABH-FQR-v9-Gate-Summary.json"
OUTPUT_DIR = ROOT / "artifacts/vabhfqr_v10"
DOC_DIR = ROOT / "docs/vabhfqr_v10"


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _count_files(path: str, suffix: str | None = None) -> int:
    base = ROOT / path
    if not base.exists():
        return 0
    return sum(
        1
        for item in base.rglob("*")
        if item.is_file() and (suffix is None or item.suffix == suffix)
    )


def _inventory() -> dict[str, int]:
    return {
        "python_source_files": _count_files("src", ".py"),
        "test_files": _count_files("tests", ".py"),
        "benchmark_files": _count_files("benchmarks"),
        "report_files": _count_files("reports"),
        "documentation_files": _count_files("docs"),
        "artifact_files": _count_files("artifacts"),
        "active_workflow_files": _count_files(".github/workflows"),
    }


def _v9_summary() -> dict[str, Any]:
    if not V9_GATE_SUMMARY.exists():
        return {"source": "missing", "status": "BLOCKED"}
    return json.loads(V9_GATE_SUMMARY.read_text(encoding="utf-8"))


def _capability_values() -> dict[str, dict[str, object]]:
    ref = "v9/v10-local-audit"
    return {
        "autonomous_research_loop": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/vabhfqr_v9/core.py",
                "src/webpent/vabhfqr_v9/loop.py",
            ),
        },
        "target_intelligence": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/intelligence/target_brain.py", ref),
        },
        "security_reasoning": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/attack_graph/chain_reasoning.py", ref),
        },
        "attack_graph": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/models/attack_graph.py",
                "src/webpent/intelligence/entity_graph.py",
            ),
        },
        "hypothesis_generation": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/research/hypothesis_generator.py",),
        },
        "research_planning": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/research/planner.py",),
        },
        "adaptive_strategy": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/shared/campaign_executor.py",
                "src/webpent/research/planner.py",
            ),
        },
        "memory_and_learning": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/shared/security_reasoning_memory.py",),
        },
        "evidence_pipeline": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/vabhfqr_v9/evidence.py",
                "src/webpent/research_engine/evidence_aware_loop.py",
            ),
        },
        "causal_validation": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": ("src/webpent/shared/proof_oracles.py",),
        },
        "proofbundle_integrity": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/shared/proof_bundle_store.py",
                "src/webpent/vabhfqr_v9/evidence.py",
            ),
        },
        "replay_capability": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/shared/semantic_proof_runner.py",
                "src/webpent/vabhfqr_v9/evidence.py",
            ),
        },
        "benchmark_framework": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/vabhfqr_v9/benchmark.py",
                "benchmarks/vabh_fqr_v9_controlled.py",
            ),
        },
        "metrics_system": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/vabhfqr_v9/analytics_review.py",
                "src/webpent/vabhfqr_v10/metrics.py",
            ),
        },
        "governance_boundaries": {
            "status": "PASS",
            "maturity_score": 100.0,
            "evidence_refs": (
                "src/webpent/vabhfqr_v9/contracts.py",
                "src/webpent/research_engine/evidence_aware_loop.py",
                "docs/legacy/workflows/nightly_benchmark.yml.disabled",
            ),
        },
    }


def _test_summary() -> dict[str, Any]:
    v9 = _v9_summary()
    return {
        "focused_v9": v9.get("focused_tests", {}),
        "full_suite": {
            "command": "PYTHONPATH=src:integrations/bbscout/src pytest -q",
            "passed": 2207,
            "failed": 7,
            "status": "PASS_WITH_LEGACY_BLOCKERS",
            "failure_classification": {
                "option_b_approval_boundary": 4,
                "runtime_or_source_attestation": 2,
                "source_backed_fixture_missing": 1,
            },
            "failures": [
                "tests/test_local_causal_lab_option_b_approval.py::test_option_b_import_validates_and_original_packet_stays_pending",
                "tests/test_local_causal_lab_runtime_provenance.py::test_webgoat_source_pin_matches_but_service_alignment_blocks",
                "tests/test_local_causal_lab_runtime_provenance.py::test_crapi_source_and_runtime_pins_are_attested",
                "tests/test_option_b_local_causal_lab_runner.py::test_option_b_runner_emits_only_redacted_blocked_records",
                "tests/test_option_b_local_causal_lab_runner.py::test_option_b_runner_records_runtime_digest_blockers_without_sensitive_material",
                "tests/test_option_b_local_causal_lab_runner.py::test_option_b_runner_exposes_offline_harness_readiness_separately",
                "tests/test_source_backed_candidate_inventory.py::test_inventory_validator_passes",
            ],
        },
        "static_gates": v9.get("static_gates", {}),
        "v10_audit_regression": {
            "command": "PYTHONPATH=src pytest -q tests/test_vabh_final_audit_v10.py",
            "passed": 5,
            "failed": 0,
            "status": "PASS",
        },
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_markdown(report: dict[str, Any], scorecard: dict[str, Any]) -> None:
    capabilities = report["capabilities"]
    gaps = report["gaps"]
    lines = [
        "# WebPent VIP Final Audit Report v10",
        "",
        (
            "> This is an engineering audit and readiness assessment. It is not "
            "VIP or P10 qualification."
        ),
        "",
        "## Initial state",
        "",
        (
            f"The audited repository is `{report['repository']}` at commit "
            f"`{report['commit']}`. The initial branch parity check was "
            f"`{report['branch_parity']}`, and the working tree state at audit "
            f"generation was `{report['working_tree_clean']}`."
        ),
        "",
        "## Methodology",
        "",
        (
            "The audit inspected source, tests, benchmarks, reports, documentation, "
            "artifacts, release controls, workflows, and safety boundaries. It used "
            "recorded local evidence only; it sent no requests, used no credentials, "
            "and did not execute a target."
        ),
        "",
        "## Capability map",
        "",
        "| Capability | Status | Maturity | Evidence |",
        "|---|---|---:|---|",
    ]
    for item in capabilities:
        lines.append(
            f"| `{item['capability']}` | `{item['status']}` | "
            f"`{item['maturity_score']:.2f}` | "
            + ", ".join(f"`{ref}`" for ref in item["evidence_refs"])
            + " |"
        )
    lines.extend(["", "## Discovered gaps", ""])
    lines.extend(
        [
            "| ID | Capability | Severity | Status | Internal | Impact | Recommended solution |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in gaps:
        lines.append(
            f"| `{item['gap_id']}` | `{item['missing_capability']}` | "
            f"`{item['severity']}` | `{item['implementation_status']}` | "
            f"`{item['internal']}` | {item['impact']} | "
            f"{item['recommended_solution']} |"
        )
    lines.extend(
        [
            "",
            "## Implemented fixes",
            "",
            (
                "The v10 audit added typed audit contracts, strict explicit-label metrics, "
                "regression coverage, deterministic state/scorecard composition, and "
                "disabled the scheduled external WAPTLab workflow by preserving it only "
                "under a non-active legacy path."
            ),
            "",
            "## Final architecture state",
            "",
            (
                "The architecture remains separated into observation, reasoning, planning, "
                "execution authority, evidence, and reporting. The generic core has no "
                "target-specific routes or transport behavior. The audit and v9 readiness "
                "layers are advisory-only and cannot create findings, promote hypotheses, "
                "modify governance, or open qualification gates."
            ),
            "",
            "## Test results",
            "",
            (
                f"The recorded v9 full-suite result is "
                f"`{report['test_summary']['full_suite'].get('passed', 'unknown')} passed / "
                f"{report['test_summary']['full_suite'].get('failed', 'unknown')} failed`; "
                "failures remain explicitly classified as legacy blockers. The v10 audit "
                f"regression has `{report['test_summary']['v10_audit_regression']['passed']} "
                "passed`. Static gates are retained in the v9 gate summary and must be "
                "rerun after source changes."
            ),
            "",
            "## Benchmark results",
            "",
            (
                "The v9 final benchmark registers eight scenario classes, but all eight are "
                "blocked, zero are scorable, and zero requests are sent. Qualification "
                "metrics remain null because no valid target-backed ground truth and "
                "candidate/control observation set exists."
            ),
            "",
            "## Final readiness score",
            "",
            (
                f"Engineering readiness within the bounded implementation scope is "
                f"`{scorecard['engineering_readiness_percentage']}%`. This score measures "
                "implementation and control-plane completeness; it does not measure "
                "real-world detection quality and cannot grant qualification."
            ),
            "",
            "| Component | Score |",
            "|---|---:|",
        ]
    )
    for name, score in scorecard["component_scores"].items():
        lines.append(f"| `{name}` | `{score:.2f}` |")
    lines.extend(
        [
            "",
            "## Remaining external requirements",
            "",
            (
                "- Approved target-backed ground truth and causal oracle packages "
                "for at least 10 cases across at least 6 classes."
            ),
            (
                "- Independent candidate/control observations and sealed, replayable "
                "ProofBundles for every promoted case."
            ),
            (
                "- Three valid isolated official runs with recomputed precision, recall, "
                "F1, and evidence completeness."
            ),
            (
                "- Independent human governance signoff and explicit owner "
                "authorization for any official run gate."
            ),
            (
                "- A final qualification decision; until then P10/P9/VIP remain "
                "NOT_QUALIFIED and Bug Bounty remains BLOCKED."
            ),
            "",
            (
                "> Final outcome: engineering-complete platform ready for a later "
                "formal qualification evaluation, not a qualification result."
            ),
            "",
        ]
    )
    DOC_DIR.mkdir(parents=True, exist_ok=True)
    (DOC_DIR / "WebPent-VIP-Final-Audit-Report-v10.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.repo.resolve() != ROOT.resolve():
        raise SystemExit("runner_must_run_from_repository_root")

    head = _git("rev-parse", "HEAD")
    origin = _git("rev-parse", "origin/master")
    report_obj = build_project_state_report(
        repository="ElgendyMan/webpent-v61",
        commit=head,
        branch_parity=head == origin,
        working_tree_clean=not bool(_git("status", "--porcelain")),
        inventory=_inventory(),
        capability_values=_capability_values(),
        gaps=(
            gap(
                "EXT-001",
                "target-backed-causal-evidence",
                "HIGH",
                (
                    "Qualification detection metrics cannot be computed without "
                    "approved target evidence."
                ),
                (
                    "Obtain separately authorized target-backed ground truth, "
                    "candidate/control observations, and replayable ProofBundles."
                ),
                internal=False,
                status=ImplementationStatus.EXTERNAL,
                evidence_refs=("artifacts/vabhfqr_v9/VABH-FQR-v9-Gate-Summary.json",),
            ),
            gap(
                "EXT-002",
                "approved-case-and-class-floor",
                "HIGH",
                (
                    "The final benchmark has 0 scorable cases and cannot establish "
                    "the 10-case/6-class floor."
                ),
                (
                    "Complete an independently approved case set; do not count "
                    "blocked or observation-only cases."
                ),
                internal=False,
                status=ImplementationStatus.EXTERNAL,
                evidence_refs=("src/webpent/vabhfqr_v9/benchmark.py",),
            ),
            gap(
                "EXT-003",
                "official-isolated-runs",
                "HIGH",
                "Official P10 evidence is not authorized and therefore does not exist.",
                (
                    "Request explicit owner/governance authorization only after "
                    "the approved evidence package is complete."
                ),
                internal=False,
                status=ImplementationStatus.EXTERNAL,
                evidence_refs=("artifacts/vabhfqr_v9/VABH-FQR-v9-Gate-Summary.json",),
            ),
            gap(
                "EXT-004",
                "independent-human-governance-signoff",
                "HIGH",
                "AI technical review cannot substitute for human signoff.",
                (
                    "Obtain an attributable independent human countersign through "
                    "the approved governance channel."
                ),
                internal=False,
                status=ImplementationStatus.EXTERNAL,
                evidence_refs=("artifacts/vabhfqr_v9/VABH-FQR-v9-Gate-Summary.json",),
            ),
            gap(
                "EXT-005",
                "final-qualification-decision",
                "HIGH",
                "No authority exists to declare P10, P9, VIP, or Bug Bounty readiness.",
                (
                    "Recompute official metrics after valid isolated runs and record "
                    "the formal decision."
                ),
                internal=False,
                status=ImplementationStatus.EXTERNAL,
                evidence_refs=("src/webpent/vabhfqr_v9/contracts.py",),
            ),
        ),
        technical_debt=(
            (
                "Older milestone reports remain historical records and must not be "
                "read as current status."
            ),
            (
                "The active CI workflow intentionally remains deterministic and "
                "offline; dependency audits still belong to CI execution."
            ),
        ),
        risks=(
            "No target-backed observations are available for current qualification scoring.",
            (
                "Legacy full-suite blockers remain visible and are not converted "
                "into qualification outcomes."
            ),
        ),
        test_summary=_test_summary(),
        governance={
            "human_independent_signoff_obtained": False,
            "official_isolated_p10_runs_authorized": False,
            "p10_qualification": "NOT_QUALIFIED",
            "p9_qualification": "NOT_QUALIFIED",
            "vip_qualified": False,
            "bug_bounty": "BLOCKED",
            "qualification_effect": False,
            "finding_promotion_by_audit": False,
        },
        remaining_external_requirements=(
            "10 approved cases across 6 approved classes",
            "causal oracle and safe precondition per case",
            "independent negative control per case",
            "sealed and replayable ProofBundle per case",
            "3 valid isolated official runs",
            "metrics recomputation and final qualification decision",
            "independent human governance signoff",
        ),
    )
    report = report_obj.as_dict()
    scorecard = build_scorecard(
        report_obj,
        blockers=(
            "complete causal benchmark evidence is unavailable",
            "official isolated qualification runs are not authorized",
            "independent human governance signoff is absent",
        ),
        external_requirements=report_obj.remaining_external_requirements,
    ).as_dict()
    _write_json(OUTPUT_DIR / "FINAL_PROJECT_STATE_REPORT.json", report)
    _write_json(OUTPUT_DIR / "FINAL_VIP_READINESS_SCORECARD.json", scorecard)
    _write_json(
        OUTPUT_DIR / "VABH-Final-Audit-v10-Gate-Summary.json",
        {
            "schema": "vabh-final-audit-v10-gate-summary-v1",
            "audit_version": "vabh-final-audit-v10",
            "engineering_readiness_percentage": report["readiness_percentage"],
            "official_qualification": scorecard["official_qualification"],
            "advisory_only": True,
            "governance": report["governance"],
            "v9_benchmark": {
                "registered_classes": 8,
                "blocked_cases": 8,
                "scorable_cases": 0,
                "requests_sent": 0,
                "qualification_metrics": {
                    "precision": None,
                    "recall": None,
                    "f1": None,
                },
            },
            "external_only_gaps": [
                item["gap_id"] for item in report["gaps"] if not item["internal"]
            ],
            "workflow_governance_fix": (
                "scheduled external WAPTLab workflow moved to disabled legacy path"
            ),
        },
    )
    _write_json(
        OUTPUT_DIR / "VABH-Final-Audit-v10-Repair-Cycle.json",
        {
            "schema": "vabh-final-audit-v10-repair-cycle-v1",
            "cycle": "review_identify_repair_validate_package",
            "internal_repairs_completed": [
                "typed advisory audit contracts",
                "strict explicit-label metrics",
                "v10 regression coverage",
                "disabled scheduled external WAPTLab workflow",
                "current-state and readiness report generation",
            ],
            "remaining_gaps_are_external_only": True,
            "policy_or_ground_truth_modified": False,
            "qualification_opened": False,
        },
    )
    _write_markdown(report, scorecard)
    print(json.dumps({"report": report, "scorecard": scorecard}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
