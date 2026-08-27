from __future__ import annotations

import copy
import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / (
    "reports/evaluation/owner_decision/"
    "TARGET-LIVE-FIXTURE-SESSION-INJECTION-OWNER-DECISION-PACKET-v1.json"
)
MODULE_PATH = ROOT / "scripts/check_target_live_fixture_session_injection_packet.py"


def load_validator():
    namespace = runpy.run_path(str(MODULE_PATH))
    return namespace["validate"]


def load_packet() -> dict:
    return json.loads(PACKET_PATH.read_text(encoding="utf-8"))


def test_target_live_packet_is_pending_and_fail_closed():
    errors = load_validator()(load_packet())
    assert errors == []


def test_packet_rejects_open_execution_gate():
    packet = copy.deepcopy(load_packet())
    packet["execution_gate"]["status"] = "OPEN"
    assert "execution_gate_must_be_closed" in load_validator()(packet)


def test_packet_rejects_target_live_ready_without_owner_approval():
    packet = copy.deepcopy(load_packet())
    packet["required_readiness_flags"]["target_live_preconditions_ready"] = True
    assert "target_live_readiness_must_remain_false_until_approval" in load_validator()(packet)


def test_packet_rejects_placeholder_or_alignment_claim():
    packet = copy.deepcopy(load_packet())
    packet["observed_provenance"]["webgoat"]["service_alignment_status"] = "verified"
    packet["observed_provenance"]["webgoat"]["build_artifact_sha256"] = "PLACEHOLDER"
    errors = load_validator()(packet)
    assert "webgoat_alignment_must_remain_not_attested" in errors
    assert "webgoat_artifact_digest_invalid" in errors
    assert "placeholder_found" in errors


def test_packet_rejects_missing_crapi_repo_digest():
    packet = copy.deepcopy(load_packet())
    packet["observed_provenance"]["crapi"]["runtime_images"][0]["repo_digest"] = "sha256:missing"
    assert "crapi_repo_digest_invalid" in load_validator()(packet)
