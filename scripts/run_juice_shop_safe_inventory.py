#!/usr/bin/env python3
"""Run bounded, read-only Juice Shop inventory observations.

This is a readiness smoke runner, not a P10 evaluator. It never promotes a case,
creates a finding, signs a ProofBundle, or stores browser state. The output is
metadata-only and intentionally contains no response bodies, headers, cookies,
credentials, or probe values.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from webpent.benchmark.juice_shop_safe_cases import JUICE_SHOP_SAFE_CASES
from webpent.shared.browser_proof_runner import EphemeralProbe
from webpent.shared.control_plane import (
    BrowserActionRequest,
    BrowserSessionRef,
    compile_scope,
    evaluate_scope,
)
from webpent.shared.control_plane_runtime import BrowserActionAdapter, BrowserSessionManager
from webpent.shared.playwright_adapter import EphemeralProbeStore, PlaywrightBrowserHandler

_ALLOWED_ORIGIN = "http://127.0.0.1:3000"
_NEUTRAL_PROBE = "p10-neutral-observation"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--origin", default=_ALLOWED_ORIGIN)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    normalized = f"{parsed.scheme.lower()}://{parsed.hostname}:{parsed.port or 80}"
    if normalized != _ALLOWED_ORIGIN:
        raise ValueError("only_loopback_juice_shop_origin_allowed")
    return normalized


def _scope(engagement_id: str):
    return compile_scope(
        engagement_id=engagement_id,
        root_domains=(_ALLOWED_ORIGIN,),
        allowed_schemes=("http",),
        allowed_ports=(3000,),
        path_rules=("/",),
        created_by="p10-safe-inventory-runner",
        approval_source="local-juice-shop-read-only-smoke",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


def _session(engagement_id: str, profile_root: Path) -> BrowserSessionRef:
    manager = BrowserSessionManager(profile_root)
    return manager.create_session(
        engagement_id=engagement_id,
        profile_ref="inventory",
        authenticated_origins=(),
        cookie_fingerprint="sha256:" + "0" * 64,
    )


def _safe_observation(outcome) -> dict[str, object]:
    observation = dict(outcome.observation or {})
    return {
        "status": outcome.status,
        "reason": outcome.reason,
        "target_backed": bool(observation.get("target_backed", False)),
        "handler_status": str(observation.get("handler_status", ""))[:40],
        "status_code": observation.get("status_code"),
        "replayable": bool(observation.get("replayable", False)),
        "network_event_count": int(observation.get("network_event_count", 0) or 0),
        "has_raw_response": False,
        "has_raw_headers": False,
        "has_cookies": False,
        "has_probe_value": False,
    }


def run(run_id: str, origin: str, output: Path) -> int:
    normalized_origin = _origin(origin)
    if not run_id or any(char in run_id for char in "/\\"):
        raise ValueError("run_id_invalid")
    profile_root = Path("/tmp") / f"webpent-p10-safe-{run_id}"
    profile_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    results: list[dict[str, object]] = []

    for index, case in enumerate(JUICE_SHOP_SAFE_CASES, start=1):
        engagement_id = f"{run_id}-case-{index:02d}"
        scope = _scope(engagement_id)
        session = _session(engagement_id, profile_root)
        probe_store = EphemeralProbeStore()
        handler = PlaywrightBrowserHandler(
            target_origin=normalized_origin,
            engagement_id=engagement_id,
            profile_root=None,
            headless=True,
            browser_timeout_ms=15_000,
            probe_resolver=probe_store.resolve,
        )
        adapter = BrowserActionAdapter(
            handler,
            probe_registrar=probe_store.put,
            probe_cleaner=probe_store.clear,
        )
        target_url = urljoin(normalized_origin + "/", case.path.lstrip("/"))
        decision = evaluate_scope(scope, target_url, method="GET")
        probe = None
        probe_ref = None
        probe_digest = None
        if case.operation == "typed_search":
            probe = EphemeralProbe.from_value(
                "candidate",
                _NEUTRAL_PROBE,
                probe_ref=f"probe://{run_id}/{case.case_id}",
            )
            probe_ref = probe.probe_ref
            probe_digest = probe.probe_digest
        request = BrowserActionRequest(
            action_id=f"{run_id}-action-{index:02d}",
            engagement_id=engagement_id,
            session_id=session.session_id,
            operation=case.operation,
            url=target_url,
            scope_decision=decision,
            timeout_ms=15_000,
            idempotency_key=f"{run_id}:case:{index:02d}",
            observation_role="inventory",
            probe_ref=probe_ref,
            probe_digest=probe_digest,
            workflow_id="juice-shop-mat-search" if case.operation == "typed_search" else None,
        )
        if probe is not None:
            adapter.register_ephemeral_probe(probe.probe_ref, _NEUTRAL_PROBE)
        try:
            outcome = adapter.execute(
                request,
                session,
                allow_operations=frozenset({case.operation}),
            )
        finally:
            if probe is not None:
                adapter.clear_ephemeral_probe(probe.probe_ref)
        results.append(
            {
                "case_id": case.case_id,
                "challenge_key": case.challenge_key,
                "category": case.category,
                "operation": case.operation,
                "oracle_id": case.oracle_id,
                "mapping_status": case.mapping_status,
                "oracle_status": case.oracle_status,
                "scope_allowed": decision.allowed,
                "observation": _safe_observation(outcome),
            }
        )

    artifact_document = {
        "schema_version": "p10.safe_inventory_smoke.v1",
        "run_id": run_id,
        "target_origin": normalized_origin,
        "case_count": len(results),
        "category_count": len({str(item["category"]) for item in results}),
        "qualification_claim": "none",
        "proof_bundle": None,
        "metrics": None,
        "results": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def main() -> int:
    args = _parse_args()
    try:
        return run(args.run_id, args.origin, Path(args.output))
    except Exception as exc:
        print(f"safe_inventory_failed:{type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
