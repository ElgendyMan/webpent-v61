#!/usr/bin/env python3
"""Build a deterministic, fail-closed traceability report for pasted_content_4.

The report is source-derived: it records referenced files, their hashes, and
whether the declared evidence exists. It never promotes missing live evidence
to a pass. WAPTLab qualification and provider live smoke remain explicit
non-qualification states unless their separately authorized artifacts exist.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_JSON = ROOT / "docs" / "plan4_traceability.json"
OUTPUT_MD = ROOT / "docs" / "PLAN4_TRACEABILITY.md"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def evidence(path_text: str) -> dict[str, Any]:
    path = ROOT / path_text
    present = path.is_file()
    return {
        "path": path_text,
        "present": present,
        "sha256": sha256_file(path) if present else None,
        "bytes": path.stat().st_size if present else None,
    }


def phase(
    phase_id: str,
    title: str,
    status: str,
    requirements: list[str],
    source_files: list[str],
    test_files: list[str],
    artifact_files: list[str],
    notes: list[str],
) -> dict[str, Any]:
    source = [evidence(item) for item in source_files]
    tests = [evidence(item) for item in test_files]
    artifacts = [evidence(item) for item in artifact_files]
    missing = [item["path"] for item in [*source, *tests, *artifacts] if not item["present"]]
    effective_status = status
    if missing and status == "PASS":
        effective_status = "EVIDENCE_INCOMPLETE"
        notes = [*notes, "Referenced evidence is missing; status was downgraded fail-closed."]
    return {
        "phase": phase_id,
        "title": title,
        "status": effective_status,
        "requirements": requirements,
        "source_files": source,
        "test_files": tests,
        "artifact_files": artifacts,
        "missing_evidence": missing,
        "notes": notes,
    }


def build_report() -> dict[str, Any]:
    phases = [
        phase(
            "P0",
            "Reproducible baseline and repository recovery",
            "PARTIAL",
            [
                "Collection/import smoke and full suites must run.",
                "Both projects must be Ruff-clean and release artifacts redaction-safe.",
            ],
            ["scripts/build_release_manifest.py", "scripts/verify_release_artifacts.py"],
            ["tests/test_release_artifact_audit.py", "tests/test_v70_release_contracts.py"],
            [
                "artifacts/smart_hunter_review/plan_baseline_20260822.log",
                "artifacts/smart_hunter_review/phase6_recheck_20260822.log",
                "docs/release_manifest.json",
            ],
            [
                "WebPent and bbscout final combined rerun is represented separately "
                "in release evidence.",
                "No generated runtime database, cache, credential, cookie, or private "
                "key is evidence for a release.",
            ],
        ),
        phase(
            "P1",
            "Repository boundary and provider-neutral contracts",
            "PASS",
            [
                "Provider-neutral records and typed failures normalize offline.",
                "Unknown/missing policy or scope cannot become ready.",
            ],
            [
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/providers/catalog.py",
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/providers/fixture.py",
            ],
            [],
            ["artifacts/smart_hunter_review/phase3_provider_tests_final.log"],
            [
                "The provider source is an external integration tree and is not claimed "
                "as committed to WebPent Git.",
                "Fixture contracts are offline and provider-neutral; they are not "
                "official live schema validation.",
            ],
        ),
        phase(
            "P2",
            "Multi-provider discovery and safe credential handling",
            "PARTIAL",
            [
                "Four provider identities have bounded read-only fixture adapters.",
                "Live smoke is separately authorized and must remain disabled otherwise.",
            ],
            [
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/providers/catalog.py",
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/cli.py",
            ],
            [],
            ["artifacts/smart_hunter_review/phase3_provider_smoke_final.log"],
            [
                "Offline fixture smoke is complete for HackerOne, Bugcrowd, Intigriti, "
                "and YesWeHack.",
                "Provider live smoke is NOT RUN: no separate provider authorization "
                "was supplied.",
                "Bugcrowd, Intigriti, and YesWeHack remain fixture-only; no live "
                "support is claimed.",
            ],
        ),
        phase(
            "P3",
            "Program selection by expected confirmed-finding yield",
            "PASS",
            [
                "Eligibility is fail-closed for stale, ambiguous, unsupported, or "
                "unevidenced programs.",
                "Ranking is deterministic and evidence-based.",
            ],
            [
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/scoring.py",
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/scope.py",
            ],
            ["tests/test_v61_remaining_plan_artifacts.py"],
            ["artifacts/smart_hunter_review/phase3_provider_tests_final.log"],
            [
                "No bounty size, brand popularity, or domain count is treated as "
                "confirmation evidence."
            ],
        ),
        phase(
            "P4",
            "Scope normalization, package signing, and admission",
            "PASS",
            [
                "Canonical scope, detached Ed25519 signing, trust-map verification, "
                "and admission are fail-closed.",
                "Replay, tamper, expiry, wrong target, and missing confirmation are "
                "denied before graph start.",
            ],
            [
                "src/webpent/shared/package_execution_intake.py",
                "src/webpent/shared/package_preflight.py",
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/packages.py",
                "../../phase6_bbscout_extract/webpent_bbscout_integration/bbscout/src/bbscout/signatures.py",
            ],
            ["tests/test_target_package_v2_hardening.py"],
            ["artifacts/smart_hunter_review/phase4_handoff_proof_validation.log"],
            [
                "Private signing keys are runtime-only and are not packaged or "
                "persisted by the CLI path."
            ],
        ),
        phase(
            "P5",
            "Complete WebPent wiring",
            "PASS",
            [
                "Signed package context survives entrypoint, intake, worker, graph, "
                "execution gate, validator, proof, and report boundaries.",
                "No alternate direct-I/O path bypasses ActionAuthority and ActionExecutor.",
            ],
            [
                "src/webpent/api/app.py",
                "src/webpent/workers/pentest_worker.py",
                "src/webpent/shared/autonomous_controller.py",
            ],
            ["tests/test_target_package_v2_hardening.py", "tests/test_autonomy_contracts.py"],
            ["artifacts/smart_hunter_review/phase4_handoff_proof_validation.log"],
            ["Evidence is dry-run/mock based; no live target was contacted."],
        ),
        phase(
            "P6",
            "Target understanding and complex-target modeling",
            "PASS",
            [
                "Target model records routes, APIs, workflows, identities, tenants, "
                "data flows, and coverage states.",
                "Hypotheses do not become findings without behavioral evidence.",
            ],
            [
                "src/webpent/knowledge/target_model.py",
                "src/webpent/knowledge/target_knowledge.py",
                "src/webpent/shared/workflow_understanding.py",
            ],
            [
                "tests/test_phase5_target_understanding.py",
                "tests/test_vip_offline_validator_fixtures.py",
            ],
            ["artifacts/smart_hunter_review/phase5_target_validator_autonomy.log"],
            [
                "The evidence is offline fixture and mock-transport evidence, not "
                "WAPTLab qualification."
            ],
        ),
        phase(
            "P7",
            "Identity, browser, mailbox, and workflow capability",
            "PARTIAL",
            [
                "Credential and browser state must be operator supplied, redaction-safe, "
                "and isolated from packages/prompts/logs.",
                "Missing identity or capability must block or remain inconclusive.",
            ],
            [
                "src/webpent/shared/identity_provisioning.py",
                "src/webpent/shared/package_execution_intake.py",
                "src/webpent/shared/direct_io_inventory.py",
            ],
            [
                "tests/test_identity_provisioning.py",
                "tests/test_v72_idor_validator_replay.py",
                "tests/test_p0_production_secrets_fail_closed.py",
            ],
            ["artifacts/smart_hunter_review/phase5_target_validator_autonomy.log"],
            [
                "Offline contracts and secret guards are tested.",
                "No authorized mailbox/browser credential workflow was executed in this run.",
            ],
        ),
        phase(
            "P8",
            "Unified execution plane and distributed safety",
            "PASS",
            [
                "Target-facing actions pass through one authority/executor plane.",
                "Retries, resume, idempotency, budgets, and worker continuity are guarded.",
            ],
            [
                "src/webpent/shared/action_authority.py",
                "src/webpent/shared/campaign_executor.py",
                "src/webpent/shared/direct_io_inventory.py",
            ],
            ["tests/test_production_deployment_contract.py", "tests/test_autonomy_contracts.py"],
            ["docs/direct_io_inventory.json"],
            [
                "G-02 is evaluated from generated inventory and runtime/precommit "
                "checks, not from a manual assertion."
            ],
        ),
        phase(
            "P9",
            "Validator and oracle expansion",
            "PASS",
            [
                "Validators require causal signals, negative controls, and "
                "proof-capable observations.",
                "Candidate, inconclusive, and confirmed states remain distinct.",
            ],
            [
                "src/webpent/validators/causal_validator.py",
                "src/webpent/validators/replay_validator.py",
                "src/webpent/validators/proof_validator.py",
            ],
            [
                "tests/test_v64_multi_agent_proof_validators.py",
                "tests/test_vip_validator_plugins.py",
            ],
            ["artifacts/smart_hunter_review/phase5_target_validator_autonomy.log"],
            [
                "No finding is promoted from URL names, status codes, response text, "
                "or LLM confidence alone."
            ],
        ),
        phase(
            "P10",
            "Autonomous research loop",
            "PASS",
            [
                "Controller consumes coverage and knowledge gaps, chooses bounded next "
                "actions, and replans within budgets.",
                "LLM remains advisory and cannot authorize or prove a finding.",
            ],
            [
                "src/webpent/shared/autonomous_controller.py",
                "src/webpent/shared/research_intelligence.py",
                "src/webpent/shared/campaign_planner.py",
            ],
            ["tests/test_v94_autonomous_controller.py", "tests/test_v3_autonomous_graph_loop.py"],
            ["artifacts/smart_hunter_review/phase5_target_validator_autonomy.log"],
            ["This proves bounded offline controller behavior, not autonomous live exploitation."],
        ),
        phase(
            "P11",
            "Proof, reporting, and evidence integrity",
            "PASS",
            [
                "Confirmed status requires a valid sealed/replayable ProofBundle with "
                "causal and negative-control evidence.",
                "Reports expose blocked and inconclusive coverage and refuse unsupported "
                "confirmation.",
            ],
            [
                "src/webpent/shared/proof_engine.py",
                "src/webpent/shared/proof_bundle_store.py",
                "src/webpent/agents/reporter/agent.py",
            ],
            [
                "tests/test_v92_reporter_strict_proof.py",
                "tests/test_vip_proof_engine.py",
                "tests/test_v64_multi_agent_proof_validators.py",
            ],
            ["artifacts/smart_hunter_review/phase4_handoff_proof_validation.log"],
            ["Proof claims here are from offline/mocked validation paths only."],
        ),
        phase(
            "P12",
            "WAPTLab qualification and complex-target optimization",
            "NOT QUALIFIED",
            [
                "Three independent clean authorized runs must confirm at least 15/20 "
                "classes.",
                "Precision must be at least 90%, reproducibility at least 95%, proof "
                "coverage 100%, and zero scope violations/duplicates/false-clean "
                "results.",
            ],
            ["scripts/run_vip_quality_gate.py"],
            ["tests/test_v61_remaining_plan_artifacts.py"],
            ["docs/waptlab_qualification_report.json"],
            [
                "NOT RUN: no authorized local WAPTLab instance, target package, or "
                "separate qualification authorization was provided.",
                "No live target/provider I/O was performed and no VIP claim is made.",
            ],
        ),
        phase(
            "P13",
            "Production hardening and release packaging",
            "PARTIAL",
            [
                "Release must be redaction-safe, reproducible, statically clean, and "
                "verifiable as an archive.",
                "Production/qualification profiles force proof requirements and remain "
                "fail-closed.",
            ],
            [
                "scripts/run_vip_quality_gate.py",
                "scripts/build_release_manifest.py",
                "scripts/verify_release_artifacts.py",
                "docker-compose.yml",
            ],
            [
                "tests/test_release_artifact_audit.py",
                "tests/test_production_deployment_contract.py",
            ],
            ["docs/vip_quality_gate.json", "docs/release_manifest.json"],
            [
                "Final combined gate and clean integration archive are generated after "
                "this report is created.",
                "Release decision must remain blocked until all required evidence and "
                "authorized qualification exist.",
            ],
        ),
    ]
    return {
        "schema_version": "plan4-traceability-v1",
        "plan_source": "pasted_content_4.txt",
        "repository": "WebPent + external bbscout integration tree",
        "git_head": git_head(),
        "python": platform.python_version(),
        "phases": phases,
        "global_safety": {
            "live_provider_io": "NOT RUN",
            "live_target_io": "NOT RUN",
            "waptlab_qualification": "NOT QUALIFIED",
            "automatic_disclosure_or_submission": "DISABLED",
            "private_keys_in_artifacts": "FORBIDDEN",
        },
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Plan P0–P13 Traceability",
        "",
        "> This report is generated from repository paths and saved evidence. "
        "Missing evidence is never promoted to PASS.",
        "",
        f"**WebPent Git HEAD:** `{report['git_head']}`",
        f"**Python:** `{report['python']}`",
        "",
        "| Phase | Status | Code files | Test files | Evidence files | Missing |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in report["phases"]:
        lines.append(
            "| {phase} | {status} | {source} | {tests} | {artifacts} | {missing} |".format(
                phase=item["phase"],
                status=item["status"],
                source=sum(entry["present"] for entry in item["source_files"]),
                tests=sum(entry["present"] for entry in item["test_files"]),
                artifacts=sum(entry["present"] for entry in item["artifact_files"]),
                missing=len(item["missing_evidence"]),
            )
        )
    lines.extend(["", "## Phase notes", ""])
    for item in report["phases"]:
        lines.append(f"### {item['phase']} — {item['title']} ({item['status']})")
        lines.append("")
        for note in item["notes"]:
            lines.append(f"- {note}")
        if item["missing_evidence"]:
            lines.append("")
            lines.append("Missing evidence:")
            for missing in item["missing_evidence"]:
                lines.append(f"- `{missing}`")
        lines.append("")
    lines.extend(
        [
            "## Safety boundary",
            "",
            "| Item | Recorded state |",
            "| --- | --- |",
            f"| Live provider I/O | `{report['global_safety']['live_provider_io']}` |",
            f"| Live target I/O | `{report['global_safety']['live_target_io']}` |",
            f"| WAPTLab qualification | `{report['global_safety']['waptlab_qualification']}` |",
            "| Automatic disclosure/submission | "
            f"`{report['global_safety']['automatic_disclosure_or_submission']}` |",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    report = build_report()
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    OUTPUT_MD.write_text(markdown(report).rstrip("\n") + "\n", encoding="utf-8")
    print(json.dumps({"json": str(OUTPUT_JSON), "markdown": str(OUTPUT_MD)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
