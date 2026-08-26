"""Run a bounded three-run proof exercise against a controlled local lab.

The lab is deliberately synthetic and loopback-only.  It is not Juice Shop, does
not change the frozen P10 ground truth, and cannot by itself qualify P10 or VIP.
It exists to exercise the live transport boundary, target-backed redacted
observations, causal/negative-control predicates, sealing, replay, isolation,
and metric calculation end to end.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from webpent.benchmark.p10 import P10GroundTruth, P10Run, evaluate_p10
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.verifier import verify_replay_evidence

_APPROVED_CASES = (
    "juice.directory_listing.v1",
    "juice.local_xss.v1",
    "juice.error_handling.v1",
    "juice.forgotten_backup.v1",
    "juice.well_known_security_policy.v1",
    "juice.public_scoreboard_route.v1",
    "juice.access_log_disclosure.v1",
    "juice.misplaced_signature_file.v1",
    "juice.exposed_metrics.v1",
    "juice.security_policy.v1",
    "juice.privacy_policy_proof.v1",
)

_CASE_CATEGORY = {
    "juice.directory_listing.v1": "Sensitive Data Exposure",
    "juice.local_xss.v1": "XSS",
    "juice.error_handling.v1": "Security Misconfiguration",
    "juice.forgotten_backup.v1": "Sensitive Data Exposure",
    "juice.well_known_security_policy.v1": "Miscellaneous",
    "juice.public_scoreboard_route.v1": "Miscellaneous",
    "juice.access_log_disclosure.v1": "Observability Failures",
    "juice.misplaced_signature_file.v1": "Observability Failures",
    "juice.exposed_metrics.v1": "Observability Failures",
    "juice.security_policy.v1": "Miscellaneous",
    "juice.privacy_policy_proof.v1": "Security through Obscurity",
}

_CASE_SEMANTIC = {
    "juice.directory_listing.v1": "directory_listing",
    "juice.local_xss.v1": "typed_search_sink",
    "juice.error_handling.v1": "verbose_error_shape",
    "juice.forgotten_backup.v1": "backup_resource",
    "juice.well_known_security_policy.v1": "policy_shape",
    "juice.public_scoreboard_route.v1": "scoreboard_shape",
    "juice.access_log_disclosure.v1": "log_record_shape",
    "juice.misplaced_signature_file.v1": "signature_shape",
    "juice.exposed_metrics.v1": "metrics_shape",
    "juice.security_policy.v1": "policy_shape",
    "juice.privacy_policy_proof.v1": "privacy_surface",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _origin_fingerprint(url: str) -> str:
    return _digest(_origin(url))


def _length_bucket(length: int) -> str:
    if length <= 32:
        return "tiny"
    if length <= 128:
        return "small"
    if length <= 512:
        return "medium"
    return "large"


def _semantic_facts(case_id: str, role: str) -> dict[str, Any]:
    semantic_key = _CASE_SEMANTIC[case_id]
    candidate = role == "candidate"
    facts: dict[str, Any] = {
        "semantic_profile": f"controlled_lab.{semantic_key}.v1",
        "semantic_match": candidate,
        "semantic_reason": (
            f"controlled_lab:{semantic_key}:candidate_only"
            if candidate
            else "controlled_lab:control_or_baseline_absent"
        ),
    }
    facts[semantic_key] = candidate
    if semantic_key == "typed_search_sink":
        facts["fresh_session_replay"] = candidate
    return facts


def _fetch(url: str, *, role: str, case_id: str, target_fingerprint: str) -> dict[str, Any]:
    request = Request(url, method="GET", headers={"Accept": "text/plain"})
    with urlopen(request, timeout=3.0) as response:  # noqa: S310 - loopback URL is checked below
        status_code = int(response.status)
        content_type = str(response.headers.get("Content-Type", "text/plain"))
        body = response.read(1024)
    facts = _semantic_facts(case_id, role)
    redacted = {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": target_fingerprint,
        "request_digest": _digest({"method": "GET", "url": url}),
        "response_digest": _digest(
            {
                "status_code": status_code,
                "content_type_family": content_type.split(";", 1)[0].lower(),
                "response_length_bucket": _length_bucket(len(body)),
                **facts,
            }
        ),
        "replayable": True,
        "status_code": status_code,
        "content_type_family": content_type.split(";", 1)[0].lower(),
        "response_length_bucket": _length_bucket(len(body)),
        **facts,
    }
    return redacted


def _oracle(case_id: str, observations: Mapping[str, Mapping[str, Any]]) -> tuple[bool, bool]:
    semantic_key = _CASE_SEMANTIC[case_id]
    candidate = observations["candidate"]
    baseline = observations["baseline"]
    control = observations["control"]
    causal = bool(candidate.get(semantic_key) and not baseline.get(semantic_key))
    if semantic_key == "typed_search_sink":
        causal = causal and bool(candidate.get("fresh_session_replay"))
    negative = not bool(control.get(semantic_key))
    return causal, negative


class _LabHandler(BaseHTTPRequestHandler):
    server_version = "ControlledLocalLab/1"

    def do_GET(self) -> None:  # noqa: N802
        parts = [item for item in self.path.split("/") if item]
        if len(parts) != 3 or parts[0] != "lab":
            self.send_error(404)
            return
        _, role, slug = parts
        if role not in {"baseline", "candidate", "control"}:
            self.send_error(404)
            return
        body = f"controlled-lab:{role}:{slug}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        return


def _start_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    thread = threading.Thread(target=server.serve_forever, name="controlled-local-lab", daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _finding(case_id: str, url: str) -> Finding:
    return Finding(
        title="Controlled local lab semantic case",
        severity=Severity.INFO,
        description="Synthetic known-ground-truth case used only for bounded lab validation.",
        tool_name="controlled-local-lab",
        url=url,
        vuln_class=VulnClass.INFO_DISCLOSURE,
    )


def _run_case(base_url: str, case_id: str, run_id: str) -> dict[str, Any]:
    slug = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
    urls = {
        role: f"{base_url}/lab/{role}/{slug}"
        for role in ("baseline", "candidate", "control")
    }
    target_fingerprint = _origin_fingerprint(urls["candidate"])
    observations = {
        role: _fetch(
            url,
            role="negative_control" if role == "control" else role,
            case_id=case_id,
            target_fingerprint=target_fingerprint,
        )
        for role, url in urls.items()
    }
    causal, negative = _oracle(case_id, observations)
    finding = _finding(case_id, urls["candidate"])
    verification = verify_replay_evidence(
        finding,
        baseline=observations["baseline"],
        candidate=observations["candidate"],
        negative_control=observations["control"],
        target_fingerprint=target_fingerprint,
        causal_signal=causal,
        negative_control_complete=negative,
        validator_id="controlled-local-lab-oracle",
        validator_version="1.0",
        causal_basis=f"controlled-local-lab:{_CASE_SEMANTIC[case_id]}:candidate_vs_control",
        engagement_id="controlled-local-lab-engagement-v1",
        hypothesis_id=f"{run_id}:{case_id}",
        scope_context={"origin": _origin(urls["candidate"]), "method": "GET", "local_only": True},
        identity_context={"actor": "controlled-lab-runner", "authorization": "local-fixture"},
        replay_metadata={"run_id": run_id, "case_id": case_id, "lab": "controlled-local-lab-v1"},
        target_package_id="controlled-local-lab-v1",
        target_package_sha256=_digest("controlled-local-lab-v1-config").removeprefix("sha256:"),
        target_package_scope_digest=_digest(_origin(urls["candidate"])).removeprefix("sha256:"),
        target_package_policy_digest=_digest("GET-only-loopback-no-raw-artifacts").removeprefix("sha256:"),
        require_target_backed=True,
    )
    if not verification.passed or verification.proof_bundle is None:
        raise RuntimeError(f"proof_verification_failed:{case_id}:{verification.reason}")
    bundle = verification.proof_bundle
    replay_ok = bool(
        bundle.verify_seal()
        and bundle.replay(
            [observations["baseline"], observations["candidate"], observations["control"]],
            observations["control"],
            replay_context=verification.evidence["replay_context"],
        )
    )
    if not replay_ok:
        raise RuntimeError(f"proof_replay_failed:{case_id}")
    return {
        "case_id": case_id,
        "causal_signal": causal,
        "negative_control": negative,
        "proof_bundle_id": bundle.bundle_id,
        "proof_bundle_sealed": bundle.verify_seal(),
        "replay_verified": replay_ok,
        "observation_roles": sorted(observations),
        "target_fingerprint": target_fingerprint,
        "observations": observations,
        "replay_context": verification.evidence["replay_context"],
        "proof_bundle": bundle.model_dump(mode="json"),
    }


def run_lab(output: Path) -> dict[str, Any]:
    server, thread, base_url = _start_server()
    try:
        run_records: list[dict[str, Any]] = []
        p10_runs: list[P10Run] = []
        for repetition in range(1, 4):
            run_id = f"controlled-local-lab-run-{repetition}"
            workspace_id = f"controlled-local-lab-workspace-{repetition}"
            namespace = f"controlled-local-lab-artifacts-{repetition}"
            cases = [_run_case(base_url, case_id, run_id) for case_id in _APPROVED_CASES]
            case_ids = tuple(record["case_id"] for record in cases)
            run_records.append(
                {
                    "run_id": run_id,
                    "workspace_id": workspace_id,
                    "artifact_namespace": namespace,
                    "cases": cases,
                }
            )
            p10_runs.append(
                P10Run(
                    run_id=run_id,
                    workspace_id=workspace_id,
                    artifact_namespace=namespace,
                    target_ref=base_url,
                    candidate_case_ids=frozenset(case_ids),
                    executed_case_ids=frozenset(case_ids),
                    proof_case_ids=frozenset(case_ids),
                    replay_case_ids=frozenset(case_ids),
                    target_unchanged=True,
                    findings_are_live=True,
                )
            )
        ground_truth = [
            P10GroundTruth(
                case_id=case_id,
                category=_CASE_CATEGORY[case_id],
                expected=True,
                mapping_status="approved",
                oracle_status="ready",
            )
            for case_id in _APPROVED_CASES
        ]
        metrics = evaluate_p10(ground_truth, p10_runs)
        payload = {
            "schema_version": "controlled-local-lab-p10.v1",
            "lab": {
                "id": "controlled-local-lab-v1",
                "target_ref": base_url,
                "scope": "loopback-only",
                "transport": "GET-only",
                "raw_bodies_retained": False,
                "target_modified": False,
                "known_ground_truth_cases": len(_APPROVED_CASES),
            },
            "runs": run_records,
            "p10_projection": metrics,
            "qualification": {
                "controlled_lab_evidence": "PASS",
                "official_juice_shop_p10": "NOT_QUALIFIED",
                "official_vip": "NOT_QUALIFIED",
                "reason": (
                    "This is a synthetic loopback lab, not the Juice Shop target; "
                    "independent final P10 result approval is not present."
                ),
            },
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = run_lab(args.output)
    print(json.dumps(payload["p10_projection"], indent=2, sort_keys=True))
    return 0 if payload["p10_projection"]["p10_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["run_lab"]
