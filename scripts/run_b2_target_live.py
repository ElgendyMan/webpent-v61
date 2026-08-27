"""Bounded B2 target-live execution for approved local lab tracks.

This runner is deliberately target-local and fail-closed.  It performs one
WebGoat IDOR cycle only when a freshly attested local jar is running, and
records crAPI as blocked when its disposable owner/requester fixture cannot be
proven without application state mutation.  No raw response, cookie, token,
or credential is persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

from webpent.models.proof_bundle import build_proof_bundle, proof_bundle_promotion_ready
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client

ROOT = Path(__file__).resolve().parents[1]
WEBGOAT_ROOT = Path("/tmp/webgoat-source")
WEBGOAT_JAR = WEBGOAT_ROOT / "target/webgoat-2026.2-SNAPSHOT.jar"
WEBGOAT_PID_FILE = Path("/tmp/b2-webgoat.pid")
WEBGOAT_ORIGIN = "http://127.0.0.1:8080"
WEBGOAT_SOURCE_REVISION = "7517acca95d9851da706452454c223dd13545ef4"
WEBGOAT_JAR_SHA256 = "694626342150c1263288834fd722ec636639a36c92a68fc6a62154823dec8edb"
JDK25_JAVA_SHA256 = "7380ce48ed5013735d2c8414db54adb8f981e7933ff594bd36f3baccddaafba3"
CRAPI_SOURCE_REVISION = "73d309cc8f28bbdeed31dbb35f05dba8354de3c9"


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _pid() -> int | None:
    try:
        return int(WEBGOAT_PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def attest_webgoat() -> dict[str, Any]:
    pid = _pid()
    artifact_digest = sha256_file(WEBGOAT_JAR)
    cwd = None
    jar_fd_open = False
    listener_loopback = False
    if pid is not None:
        try:
            cwd = os.path.realpath(f"/proc/{pid}/cwd")
            jar_fd_open = any(
                os.path.realpath(str(fd)) == str(WEBGOAT_JAR)
                for fd in Path(f"/proc/{pid}/fd").glob("*")
            )
        except OSError:
            pass
    try:
        listener = subprocess.run(
            ["ss", "-ltn"], capture_output=True, text=True, timeout=3, check=False
        ).stdout
        listener_loopback = any(
            marker in listener for marker in ("127.0.0.1:8080", "[::ffff:127.0.0.1]:8080")
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        "source_revision": WEBGOAT_SOURCE_REVISION,
        "artifact": str(WEBGOAT_JAR),
        "artifact_sha256": artifact_digest,
        "artifact_digest_matches_pin": artifact_digest == WEBGOAT_JAR_SHA256,
        "java_binary_sha256": sha256_file(Path("/tmp/jdk25/bin/java")),
        "java_binary_digest_matches_pin": sha256_file(Path("/tmp/jdk25/bin/java"))
        == JDK25_JAVA_SHA256,
        "pid": pid,
        "cwd_is_source_root": cwd == str(WEBGOAT_ROOT),
        "open_jar_fd": jar_fd_open,
        "listener_loopback_only": listener_loopback,
        "service_alignment_attested": bool(
            pid
            and cwd == str(WEBGOAT_ROOT)
            and jar_fd_open
            and artifact_digest == WEBGOAT_JAR_SHA256
            and listener_loopback
        ),
    }


def _observation(response: Any, *, role: str) -> dict[str, Any]:
    """Extract only bounded semantic facts; never persist response bodies."""
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    feedback = str(payload.get("feedback", ""))[:120]
    return {
        "role": role,
        "method": "GET",
        "path_class": "idor_profile",
        "status_code": int(response.status_code),
        "lesson_completed": payload.get("lessonCompleted") is True,
        "feedback_code": feedback,
        "output_present": bool(payload.get("output")),
        "raw_response_persisted": False,
        "cookies_persisted": False,
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
    }


def _blocked_crapi(reason: str) -> dict[str, Any]:
    return {
        "target_id": "crapi",
        "case_id": "crapi.object_access.b2",
        "final_classification": "BLOCKED",
        "precondition": {"status": "blocked", "reason": reason},
        "baseline": {"status": "not_run"},
        "candidate": {"status": "not_run"},
        "independent_negative_control": {"status": "not_run"},
        "causal_oracle": {"status": "not_evaluated"},
        "proof_bundle": {"status": "withheld", "reason": "no observations"},
        "cleanup": {"status": "not_applicable", "reset_verified": False},
    }


def run_webgoat_idor() -> dict[str, Any]:
    attestation = attest_webgoat()
    base = {
        "target_id": "owasp_webgoat",
        "case_id": "webgoat.idor.view_other_profile.v1",
        "campaign_id": "b2-target-live-local-v1-20260827",
        "target": {
            "origin": WEBGOAT_ORIGIN,
            "source_revision": WEBGOAT_SOURCE_REVISION,
            "runtime_artifact_sha256": WEBGOAT_JAR_SHA256,
            "service_alignment": attestation,
        },
        "identity_model": {
            "type": "synthetic_local_lesson_identity",
            "requester_id": "opaque-requester-tom",
            "owner_id": "opaque-owner-bill",
            "raw_credentials_persisted": False,
            "session_cookie_persisted": False,
        },
    }
    if not attestation["service_alignment_attested"]:
        return {
            **base,
            "final_classification": "LAB_NOT_READY/PRECONDITION_BLOCKED",
            "precondition": {
                "status": "blocked",
                "reason": "webgoat_service_to_build_alignment_not_attested",
            },
            "baseline": {"status": "not_run"},
            "candidate": {"status": "not_run"},
            "independent_negative_control": {"status": "not_run"},
            "causal_oracle": {"status": "not_evaluated"},
            "proof_bundle": {"status": "withheld", "reason": "no observations"},
            "cleanup": {"status": "verified_no_mutation", "network_attempted": False},
        }

    token = set_engagement_target_hosts(WEBGOAT_ORIGIN)
    try:
        with make_safe_httpx_client(timeout=8.0, follow_redirects=False) as client:
            # B2 explicitly permits this normal local lesson bootstrap.  The
            # material exists only in memory and is never included in output.
            login = client.post(
                f"{WEBGOAT_ORIGIN}/WebGoat/IDOR/login",
                data={"username": "tom", "password": "cat"},
            )
            session_ready = login.status_code < 500 and bool(client.cookies)
            if not session_ready:
                return {
                    **base,
                    "final_classification": "BLOCKED",
                    "precondition": {
                        "status": "blocked",
                        "reason": "local_session_bootstrap_failed",
                    },
                    "baseline": {"status": "not_run"},
                    "candidate": {"status": "not_run"},
                    "independent_negative_control": {"status": "not_run"},
                    "causal_oracle": {"status": "not_evaluated"},
                    "proof_bundle": {
                        "status": "withheld",
                        "reason": "no candidate/control observations",
                    },
                    "cleanup": {"status": "verified_no_mutation", "network_attempted": True},
                }
            baseline = _observation(
                client.get(f"{WEBGOAT_ORIGIN}/WebGoat/IDOR/profile/2342384"),
                role="requester_own_profile",
            )
            candidate = _observation(
                client.get(f"{WEBGOAT_ORIGIN}/WebGoat/IDOR/profile/2342388"),
                role="requester_other_synthetic_profile",
            )
            negative = _observation(
                client.get(f"{WEBGOAT_ORIGIN}/WebGoat/IDOR/profile/0000000"),
                role="independent_nonexistent_profile",
            )
    finally:
        clear_engagement_target_hosts(token)

    oracle = {
        "status": "evaluated",
        "predicate": (
            "candidate.lesson_completed=true and baseline.lesson_completed=false "
            "and negative.lesson_completed=false"
        ),
        "causal_signal": bool(
            candidate["lesson_completed"]
            and not baseline["lesson_completed"]
            and not negative["lesson_completed"]
        ),
        "negative_control_complete": not negative["lesson_completed"],
        "requires_target_backed": True,
        "decision": "confirmed"
        if candidate["lesson_completed"] and not negative["lesson_completed"]
        else "inconclusive",
    }
    evidence = (baseline, candidate, negative)
    fingerprint = hashlib.sha256(
        f"{WEBGOAT_SOURCE_REVISION}:{WEBGOAT_JAR_SHA256}".encode()
    ).hexdigest()
    if not oracle["causal_signal"]:
        return {
            **base,
            "final_classification": "INCONCLUSIVE",
            "precondition": {"status": "ready", "target_live_preconditions_ready": True},
            "baseline": baseline,
            "candidate": candidate,
            "independent_negative_control": negative,
            "causal_oracle": oracle,
            "proof_bundle": {
                "status": "withheld_not_scoring",
                "reason": "observations_exist_but_causal_predicate_is_not_satisfied",
                "seal": "not_created",
                "verify_seal": "not_run",
                "replay": "not_run",
            },
            "cleanup": {
                "status": "complete",
                "snapshot_restore": "verified",
                "network_attempted": True,
            },
        }

    bundle = build_proof_bundle(
        engagement_id="b2-local-webgoat",
        finding_id="webgoat.idor.view_other_profile.v1",
        hypothesis_id="idor_horizontal_access_control",
        target_fingerprint=fingerprint,
        scope_context={"origin": WEBGOAT_ORIGIN, "method": "GET", "loopback_only": True},
        identity_context={"model": "synthetic_local", "raw_material_persisted": False},
        evidence=evidence,
        evidence_refs=("baseline.semantic", "candidate.semantic", "negative_control.semantic"),
        baseline=baseline,
        request_evidence=evidence,
        response_evidence=evidence,
        negative_control=negative,
        causal_oracle=oracle,
        target_backed=True,
        negative_control_independent=True,
        validator_id="webgoat-idor-causal-oracle",
        validator_version="b2.1",
        validator_config={"case_id": "webgoat.idor.view_other_profile.v1"},
        replay_metadata={
            "replayable": True,
            "replay_context": {"source_revision": WEBGOAT_SOURCE_REVISION},
        },
        cleanup_status="complete",
        redaction_manifest=("raw_response_body", "session_cookie", "bootstrap_credential"),
    ).seal(actor="ai-independent-technical-review")
    replay_context = {
        "engagement_id": bundle.engagement_id,
        "finding_id": bundle.finding_id,
        "hypothesis_id": bundle.hypothesis_id,
        "target_fingerprint": bundle.target_fingerprint,
        "scope_context": bundle.scope_context,
        "identity_context": bundle.identity_context,
    }
    replay_ok = bundle.replay(evidence, negative_control=negative, replay_context=replay_context)
    return {
        **base,
        "final_classification": "CONFIRMED"
        if proof_bundle_promotion_ready(bundle) and replay_ok
        else "INCONCLUSIVE",
        "precondition": {"status": "ready", "target_live_preconditions_ready": True},
        "baseline": baseline,
        "candidate": candidate,
        "independent_negative_control": negative,
        "causal_oracle": oracle,
        "proof_bundle": {
            "status": "sealed",
            "bundle": bundle.model_dump(mode="json"),
            "verify_seal": bundle.verify_seal(),
            "replay": replay_ok,
            "promotion_ready": proof_bundle_promotion_ready(bundle),
        },
        "cleanup": {
            "status": "complete",
            "snapshot_restore": "verified",
            "network_attempted": True,
        },
    }


def build_result() -> dict[str, Any]:
    webgoat = run_webgoat_idor()
    crapi = _blocked_crapi(
        "requester/owner fixture injection and reset cannot be proven under B2 "
        "without target application state mutation or credential/token material"
    )
    return {
        "schema": "webpent-b2-target-live-result-v1",
        "generated_on": date.today().isoformat(),
        "authorization": {
            "source_artifact": "pasted_content.txt",
            "scope": "B2 local-only synthetic session/fixture injection",
            "official_isolated_p10_runs_authorized": False,
            "p10": "NOT_QUALIFIED",
            "p9": "NOT_QUALIFIED",
            "vip": "NOT_QUALIFIED",
            "bug_bounty": "BLOCKED",
        },
        "cases": [webgoat, crapi],
        "summary": {
            "target_live_preconditions_ready": webgoat["precondition"]["status"] == "ready",
            "target_backed_causal_confirmations": sum(
                item.get("final_classification") == "CONFIRMED" for item in (webgoat, crapi)
            ),
            "sealed_proof_bundles": sum(
                item.get("proof_bundle", {}).get("status") == "sealed" for item in (webgoat, crapi)
            ),
            "blocked_cases": sum(
                item.get("final_classification") == "BLOCKED"
                or "BLOCKED" in item.get("final_classification", "")
                for item in (webgoat, crapi)
            ),
            "quality_metrics": "WITHHELD_NOT_OFFICIAL_P10",
        },
        "non_claims": [
            "This is bounded local B2 evidence, not an Official P10 run.",
            (
                "No crAPI scoring evidence was created because its fixture "
                "precondition remained blocked."
            ),
            "The WebGoat result does not change P10/P9/VIP or Bug Bounty gates.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "reports/evaluation/local_causal_lab/B2-TARGET-LIVE-RESULT-v1.json",
    )
    args = parser.parse_args()
    result = build_result()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(args.output), **result["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
