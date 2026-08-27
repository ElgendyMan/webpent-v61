"""Run the bounded, fail-closed Option B local causal-lab precondition pass.

At the current authorization boundary every selected case is expected to stop
before network I/O because authentication/session or a safe disposable
fixture is unavailable.  This runner therefore emits auditable blocked
records; it does not invent target evidence and has no state-changing path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

try:
    from scripts.check_local_causal_lab_option_b_approval import (
        validate as validate_approval,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from check_local_causal_lab_option_b_approval import validate as validate_approval

from webpent.adapters.crapi.option_b import (
    CRAPI_RUNTIME_DIGEST,
    CRAPI_RUNTIME_IMAGE_DIGESTS,
    CRAPI_RUNTIME_STATUS,
    CRAPI_SERVICE_ALIGNMENT_STATUS,
    CRAPI_SOURCE_FILES,
    CRAPI_SOURCE_REVISION,
)
from webpent.adapters.crapi.option_b import (
    cases as crapi_cases,
)
from webpent.adapters.local_causal_lab.fixtures import build_regression_fixture
from webpent.adapters.local_causal_lab.option_b_contract import (
    OptionBCase,
    blocked_precondition,
    validate_loopback_get,
    validate_option_b_preconditions,
)
from webpent.adapters.local_causal_lab.runtime_provenance import (
    RuntimeProvenance,
    readiness_check,
)
from webpent.adapters.local_causal_lab.session_harness import (
    harness_snapshot_restore_check,
)
from webpent.adapters.webgoat.option_b import (
    WEBGOAT_RUNTIME_DIGEST,
    WEBGOAT_RUNTIME_DIGEST_STATUS,
    WEBGOAT_SERVICE_ALIGNMENT_STATUS,
    WEBGOAT_SOURCE_FILES,
    WEBGOAT_SOURCE_REVISION,
    WEBGOAT_TOOLCHAIN_DIGEST,
)
from webpent.adapters.webgoat.option_b import (
    cases as webgoat_cases,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT / "reports/evaluation/local_causal_lab/OPTION-B-LOCAL-CAUSAL-LAB-RESULT-v1.json"
)
SOURCE_ROOTS = {
    "owasp_webgoat": Path("/tmp/webgoat-source"),
    "crapi": Path("/tmp/crapi-source"),
}


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def collect_java_version() -> str | None:
    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    first_line = (result.stderr or result.stdout).splitlines()
    return first_line[0][:120] if first_line else None


def source_manifest(target_id: str, files: dict[str, dict[str, str]]) -> dict[str, Any]:
    root = SOURCE_ROOTS[target_id]
    entries: list[dict[str, Any]] = []
    for name, item in sorted(files.items()):
        path = root / item["path"]
        actual = sha256_file(path)
        entries.append(
            {
                "name": name,
                "path": item["path"],
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
                "matches_expected": actual == item["sha256"],
            }
        )
        if "route_file_sha256" in item:
            route_path = root / (
                "services/community/api/router/routes.go"
                if name == "community_post"
                else "services/workshop/crapi/mechanic/urls.py"
            )
            route_actual = sha256_file(route_path)
            entries[-1]["route_file"] = str(route_path.relative_to(root))
            entries[-1]["route_expected_sha256"] = item["route_file_sha256"]
            entries[-1]["route_actual_sha256"] = route_actual
            entries[-1]["route_matches_expected"] = route_actual == item["route_file_sha256"]
    return {
        "source_revision": WEBGOAT_SOURCE_REVISION
        if target_id == "owasp_webgoat"
        else CRAPI_SOURCE_REVISION,
        "source_root": str(root),
        "files": entries,
        "all_files_match": all(
            entry["matches_expected"] and entry.get("route_matches_expected", True)
            for entry in entries
        ),
    }


def target_provenance(target_id: str) -> dict[str, Any]:
    if target_id == "owasp_webgoat":
        source = source_manifest(target_id, WEBGOAT_SOURCE_FILES)
        pinned = RuntimeProvenance(
            target_id=target_id,
            source_revision=WEBGOAT_SOURCE_REVISION,
            source_files=tuple(
                (name, item["path"], item["sha256"])
                for name, item in WEBGOAT_SOURCE_FILES.items()
            ),
            runtime_digest_status=WEBGOAT_RUNTIME_DIGEST_STATUS,
            runtime_digest=WEBGOAT_RUNTIME_DIGEST,
            toolchain_digest=WEBGOAT_TOOLCHAIN_DIGEST,
            service_alignment_status=WEBGOAT_SERVICE_ALIGNMENT_STATUS,
        )
        return {
            "target_id": target_id,
            "origin": "http://127.0.0.1:8080",
            "source": source,
            "runtime": {
                "java_version": collect_java_version(),
                **pinned.as_dict(),
                "readiness": readiness_check(pinned, SOURCE_ROOTS[target_id]),
            },
        }
    source = source_manifest(target_id, CRAPI_SOURCE_FILES)
    pinned = RuntimeProvenance(
        target_id=target_id,
        source_revision=CRAPI_SOURCE_REVISION,
        source_files=tuple(
            (name, item["path"], item["sha256"])
            for name, item in CRAPI_SOURCE_FILES.items()
        ),
        runtime_digest_status=CRAPI_RUNTIME_STATUS,
        runtime_digest=CRAPI_RUNTIME_DIGEST,
        service_alignment_status=CRAPI_SERVICE_ALIGNMENT_STATUS,
        image_digests=CRAPI_RUNTIME_IMAGE_DIGESTS,
    )
    return {
        "target_id": target_id,
        "origin": "http://127.0.0.1:8888",
        "source": source,
        "runtime": {
            **pinned.as_dict(),
            "readiness": readiness_check(pinned, SOURCE_ROOTS[target_id]),
        },
    }


PREFLIGHT_URLS = {
    "webgoat.idor.view_other_profile.v1": (
        "http://127.0.0.1:8080/WebGoat/IDOR/profile/synthetic-subject"
    ),
    "webgoat.path_traversal.v1": (
        "http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=cat.jpg"
    ),
    "crapi.profile_video_object_access.v1": (
        "http://127.0.0.1:8888/identity/api/v2/user/videos/1"
    ),
    "crapi.vehicle_location_bola.v1": (
        "http://127.0.0.1:8888/identity/api/v2/vehicle/00000000-0000-0000-0000-000000000001/location"
    ),
    "crapi.community_post_object_access.v1": (
        "http://127.0.0.1:8888/community/api/v2/community/posts/1"
    ),
    "crapi.mechanic_report_object_access.v1": (
        "http://127.0.0.1:8888/workshop/api/mechanic/mechanic_report?report_id=1"
    ),
}


def case_record(case: OptionBCase, provenance: dict[str, Any]) -> dict[str, Any]:
    source_ok = provenance["source"]["all_files_match"]
    runtime = provenance["runtime"]
    runtime_ok = runtime["runtime_digest"] is not None
    readiness = runtime["readiness"]
    precondition = blocked_precondition(case)
    fixture_readiness = build_regression_fixture(case.target_id).snapshot_restore_check()
    network_scope_errors = validate_loopback_get(
        case=case,
        method="GET",
        url=PREFLIGHT_URLS[case.case_id],
        expected_origin=provenance["origin"],
    )
    harness_readiness = harness_snapshot_restore_check(case.target_id)
    target_live_readiness = {
        "runtime_digest_verified": runtime_ok and readiness["status"] == "ready",
        "network_scope_verified": not network_scope_errors,
        "service_alignment_verified": runtime["service_alignment_status"] == "attested",
        "target_fixture_injected": False,
        "auth_session_available": False,
    }
    preflight = validate_option_b_preconditions(
        case=case,
        method="GET",
        url=PREFLIGHT_URLS[case.case_id],
        expected_origin=provenance["origin"],
        readiness_status=readiness["status"],
        fixture_snapshot_status=fixture_readiness["status"],
    )
    precondition["preflight"] = preflight
    reason = case.precondition_reason
    if not source_ok:
        reason = "Source file digest drift prevents execution: " + reason
    if not runtime_ok:
        reason = "Runtime/build digest unavailable: " + reason
    if readiness["status"] != "ready":
        reason = "Lab readiness is blocked: " + "; ".join(readiness["errors"])
    if fixture_readiness["status"] != "verified":
        reason = "Offline fixture snapshot/restore failed: " + reason
    return {
        "case_id": case.case_id,
        "target_id": case.target_id,
        "track": case.track,
        "approved_track": True,
        "lab_status": "LAB_NOT_READY",
        "precondition_classification": "PRECONDITION_BLOCKED",
        "runnable_precondition": {
            **precondition,
            "source_digest_ok": source_ok,
            "runtime_digest_ok": runtime_ok,
            "runtime_readiness": readiness["status"],
            "service_alignment_status": runtime["service_alignment_status"],
            "offline_harness_readiness": harness_readiness,
            "target_live_readiness": target_live_readiness,
            "target_live_preconditions_ready": preflight["status"] == "ready"
            and target_live_readiness["runtime_digest_verified"]
            and target_live_readiness["service_alignment_verified"]
            and target_live_readiness["auth_session_available"],
            "preflight": preflight,
        },
        "identity_model": {
            "status": "offline_opaque_only",
            "credentials_or_sessions_created": False,
        },
        "fixture_model": {
            "status": "offline_snapshot_restore_verified",
            "target_fixture_injected": False,
            "reset_endpoint_called": False,
            "snapshot_restore": fixture_readiness,
            "session_harness": harness_readiness,
        },
        "baseline": {"status": "not_run", "reason": "precondition_blocked"},
        "candidate": {"status": "not_run", "reason": "precondition_blocked"},
        "independent_negative_control": {"status": "not_run", "reason": "precondition_blocked"},
        "causal_oracle": {
            "status": "not_evaluated",
            "reason": "no target-backed candidate/control observations",
        },
        "proof_bundle": {
            "status": "withheld_not_applicable",
            "seal": "not_created",
            "verify_seal": "not_run",
            "replay": "not_run",
            "reason": (
                "Proof requires target-backed baseline/candidate/control "
                "observations; none were collected."
            ),
        },
        "cleanup": {
            "status": "verified_no_mutation",
            "state_hash": fixture_readiness["restored_state_hash"],
            "reset_invoked": False,
            "network_attempted": False,
        },
        "failure_record": {
            "failure_id": f"{case.case_id}:precondition",
            "stage": "precondition",
            "code": "OPTION_B_PRECONDITION_BLOCKED",
            "reason": reason,
        },
        "root_cause_analysis": {
            "root_cause": (
                "target_local prerequisite is unavailable under the approved "
                "GET-only/no-credentials boundary"
            ),
            "evidence": [case.precondition_reason, *preflight["errors"]],
            "generic_or_target_local": "target-local",
            "safety_determination": "safe_stop_before_network",
        },
        "improvement_proposal": {
            "status": "proposal_only",
            "proposal": (
                "Keep offline fixtures for regression and require a separately "
                "authorized, non-credential target fixture/session mechanism before "
                "any live case; do not implement an auth bypass or broaden core."
            ),
            "implementation": "not_implemented",
            "regression": "precondition and snapshot/restore blocker regression added",
        },
        "before_after": {
            "before": "LAB_NOT_READY/PRECONDITION_BLOCKED",
            "after": "LAB_NOT_READY/PRECONDITION_BLOCKED",
            "comparison": "No false improvement claimed; no network or state change occurred.",
        },
        "final_classification": "LAB_NOT_READY/PRECONDITION_BLOCKED",
        "quality_metrics": (
            "WITHHELD_NO_ADMITTED_GROUND_TRUTH_OR_TARGET_EVIDENCE"
        ),
    }


def build_result(
    import_path: Path = ROOT
    / "reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json",
) -> dict[str, Any]:
    approval_errors = validate_approval(import_path=import_path)
    if approval_errors:
        raise ValueError("approval_boundary_failed:" + ",".join(approval_errors))
    provenance = {
        target_id: target_provenance(target_id) for target_id in ("owasp_webgoat", "crapi")
    }
    cases: Iterable[OptionBCase] = (*webgoat_cases(), *crapi_cases())
    records = [case_record(case, provenance[case.target_id]) for case in cases]
    return {
        "schema": "webpent-option-b-local-causal-lab-result-v2",
        "campaign_id": "option-b-local-causal-lab-v1-20260827",
        "generated_on": date.today().isoformat(),
        "authorization_ref": str(import_path.relative_to(ROOT)),
        "authorization_status": "IMPORTED_BOUNDED_DIRECTIVE",
        "scope": {
            "loopback_only": True,
            "same_origin_only": True,
            "methods": ["GET"],
            "redirect_following": False,
            "external_callbacks_or_oast": False,
            "raw_response_persistence": False,
            "official_isolated_p10_runs_authorized": False,
            "bug_bounty": "BLOCKED",
        },
        "target_provenance": provenance,
        "cases": records,
        "readiness": {
            "offline_harness": {
                "status": "ready"
                if all(
                    record["fixture_model"]["session_harness"]["status"] == "ready"
                    for record in records
                )
                else "blocked",
                "preconditions_ready": all(
                    record["fixture_model"]["session_harness"]["preconditions_ready"]
                    for record in records
                ),
                "fixture_ready": all(
                    record["fixture_model"]["session_harness"]["fixture_ready"]
                    for record in records
                ),
                "identity_model_ready": all(
                    record["fixture_model"]["session_harness"]["identity_model_ready"]
                    for record in records
                ),
                "reset_verified": all(
                    record["fixture_model"]["session_harness"]["reset_verified"]
                    for record in records
                ),
                "runtime_digest_verified": all(
                    record["fixture_model"]["session_harness"]["runtime_digest_verified"]
                    for record in records
                ),
                "network_scope_verified": all(
                    record["fixture_model"]["session_harness"]["network_scope_verified"]
                    for record in records
                ),
            },
            "target_live": {
                "status": "ready"
                if all(
                    record["runnable_precondition"]["target_live_preconditions_ready"]
                    for record in records
                )
                else "blocked",
                "preconditions_ready": all(
                    record["runnable_precondition"]["target_live_preconditions_ready"]
                    for record in records
                ),
            },
        },
        "summary": {
            "lab_status": "LAB_NOT_READY",
            "precondition_blocked_case_count": len(records),
            "approved_case_count": len(records),
            "blocked_case_count": len(records),
            "target_backed_causal_confirmations": 0,
            "proof_bundles_sealed": 0,
            "quality_metrics": "WITHHELD",
            "p10": "NOT_QUALIFIED",
            "p9": "NOT_QUALIFIED",
            "vip": "NOT_QUALIFIED",
        },
        "non_claims": [
            "No target-backed causal evidence was collected in this precondition pass.",
            "Blocked cases are not TP, FP, FN, clean, or confirmed.",
            (
                "This artifact is not an Official P10 run and does not change "
                "scoring or qualification state."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--approval-import",
        type=Path,
        default=(
            ROOT
            / "reports/evaluation/owner_decision/"
            "LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json"
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_result(args.approval_import)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "written": str(args.output),
                "cases": len(result["cases"]),
                "blocked": result["summary"]["blocked_case_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
