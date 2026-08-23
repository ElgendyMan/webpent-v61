from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from webpent.shared.bbscout_bridge import (
    BbscoutBridgeError,
    admit_bbscout_package,
    enforce_bbscout_allowlist,
    load_bbscout_package,
)


def _digest(package: dict) -> str:
    unsigned = json.loads(json.dumps(package))
    integrity = unsigned.setdefault("integrity", {})
    integrity.pop("content_sha256", None)
    integrity.pop("detached_signature", None)
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def package_fixture() -> dict:
    package = {
        "package_id": "bbscout-local-001",
        "schema_version": "target-package.schema.v2",
        "provider": "hackerone",
        "program": {
            "stable_program_id": "program-001",
            "handle": "authorized-lab",
            "name": "Authorized Lab",
        },
        "package_status": "ready",
        "source": {
            "retrieved_at": "2026-08-23T00:00:00Z",
            "source_response_sha256": "a" * 64,
        },
        "authorization": {
            "user_confirmed": True,
            "read_only_discovery": True,
            "package_expires_at": (
                datetime.now(UTC) + timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
            "revoked": False,
            "revocation_state": "active",
        },
        "policy": {
            "policy_present": True,
            "enforcement_state": "reviewed_as_provider_source_only",
        },
        "scope": {
            "status": "ready",
            "normalized_rules": [
                {"asset_type": "url", "host": "authorized.example", "action": "include"}
            ],
        },
        "capability_profile": {
            "qualified_capabilities": {"api": True, "browser": True},
            "validators": {"idor": True, "xss": True, "ssrf": False},
        },
        "selection": {"score": 72.5, "confidence": "high"},
        "integrity": {
            "content_sha256": "0" * 64,
            "signature_state": "unsigned-local-mvp",
        },
        "redaction": {"secret_scan": "passed"},
        "provenance": {"adapter_version": "fixture-v1"},
    }
    package["integrity"]["content_sha256"] = _digest(package)
    return package


def test_offline_admission_is_read_only_and_redaction_safe():
    result = admit_bbscout_package(package_fixture(), mode="offline")
    assert result.live_ready is False
    assert result.provider == "hackerone"
    assert result.qualified_capabilities == ("api", "browser")
    state = result.as_state()
    assert state["bbscout"]["live_ready"] is False
    assert "source" not in state["target_package"]
    assert "authorization" not in state["target_package"]
    assert state["target_package"]["selection"]["score"] == 72.5


def test_unsigned_local_package_is_rejected_for_live_mode():
    with pytest.raises(BbscoutBridgeError, match="detached_signature_not_verified"):
        admit_bbscout_package(package_fixture(), mode="live")


def test_non_read_only_discovery_is_rejected():
    package = package_fixture()
    package["authorization"]["read_only_discovery"] = False
    package["integrity"]["content_sha256"] = _digest(package)
    with pytest.raises(BbscoutBridgeError, match="read_only"):
        admit_bbscout_package(package)


def test_provider_submission_policy_is_rejected():
    package = package_fixture()
    package["policy"]["enforcement_state"] = "provider_submission_enabled"
    package["integrity"]["content_sha256"] = _digest(package)
    with pytest.raises(BbscoutBridgeError, match="provider_source_only"):
        admit_bbscout_package(package)


def test_allowlist_rejects_unapproved_provider_or_program():
    admission = admit_bbscout_package(package_fixture())
    with pytest.raises(BbscoutBridgeError, match="provider_not_allowlisted"):
        enforce_bbscout_allowlist(admission, provider_ids="bugcrowd")
    with pytest.raises(BbscoutBridgeError, match="program_not_allowlisted"):
        enforce_bbscout_allowlist(admission, program_ids="different-program")
    assert enforce_bbscout_allowlist(
        admission,
        provider_ids="hackerone",
        program_ids="program-001",
    ) is admission


def test_loader_rejects_symlink_and_accepts_local_json(tmp_path):
    package_path = tmp_path / "package.json"
    package_path.write_text(json.dumps(package_fixture()), encoding="utf-8")
    loaded = load_bbscout_package(package_path)
    assert loaded.context.package_id == "bbscout-local-001"
    symlink = tmp_path / "package-link.json"
    symlink.symlink_to(package_path)
    with pytest.raises(BbscoutBridgeError, match="file_invalid"):
        load_bbscout_package(symlink)
