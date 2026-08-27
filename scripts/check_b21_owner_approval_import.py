#!/usr/bin/env python3
"""Validate the bounded B2.1 owner-directive import without persisting raw approval text."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORT = ROOT / "reports/evaluation/owner_decision/B2.1-WEBGOAT-IDOR-OWNER-APPROVAL-IMPORT-v1.json"
SOURCE = Path("/home/ubuntu/upload/pasted_content_2.txt")


def main() -> int:
    data = json.loads(IMPORT.read_text(encoding="utf-8"))
    assert data["schema"] == "webpent-owner-directive-import-b2.1-v1"
    assert data["record_type"] == "owner_directive_import_execution_only"
    assert data["status"] == "IMPORTED_BOUNDED_DIRECTIVE"
    source = data["source_artifact"]
    assert source["raw_content_persisted_in_repo"] is False
    assert SOURCE.is_file()
    assert source["sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    authority = data["authority"]
    assert authority["owner_identity_provided"] is False
    assert authority["owner_signature_provided"] is False
    assert authority["human_independent_signoff_obtained"] is False
    assert authority["execution_scope"] == "B2.1 current bounded task only"
    target = data["approved_target"]
    assert target == {
        "target_id": "owasp_webgoat",
        "source_revision": "7517acca95d9851da706452454c223dd13545ef4",
        "scope": "local loopback only",
    }
    assert data["approved_case_ids"] == ["webgoat.idor.view_other_profile.v1"]
    assert data["approved_methods"] == ["GET"]
    auth = data["approved_authentication"]
    assert auth["normal_local_authentication"] is True
    assert auth["synthetic_accounts_only"] is True
    assert auth["synthetic_session_memory_only"] is True
    assert auth["real_credentials_allowed"] is False
    assert auth["credential_token_cookie_persistence_allowed"] is False
    assert auth["auth_bypass_allowed"] is False
    state = data["approved_state_boundary"]
    assert state["disposable_fixture_only"] is True
    assert state["snapshot_restore_required"] is True
    assert state["additional_state_mutation_allowed"] is False
    assert state["reset_endpoint_allowed"] is False
    assert state["external_callbacks_allowed"] is False
    qualification = data["qualification_state"]
    assert qualification == {
        "official_isolated_p10_runs_authorized": False,
        "p10": "NOT_QUALIFIED",
        "p9": "NOT_QUALIFIED",
        "vip": "NOT_QUALIFIED",
        "bug_bounty": "BLOCKED",
    }
    print("PASS: B2.1 owner-directive import is bounded and fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
