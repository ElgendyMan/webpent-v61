"""Regression tests for progress-aware payload-optimizer routing."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _finding(**overrides):
    finding = {
        "id": str(uuid.uuid4()),
        "severity": "high",
        "vuln_class": "xss",
        "confidence": "tentative",
        "confidence_level": "Pending",
        "tool_name": "test-validator",
        "url": "http://target.example/search?q=old-value",
        "target_param": "q",
        "request_method": "GET",
        "title": "Reflected XSS",
        "description": "A controlled reflection candidate.",
        "evidence": {"validation_failure_reason": "tool_no_marker"},
    }
    finding.update(overrides)
    return finding


def _state(finding, payloads=("<probe-a>",), **overrides):
    state = {
        "findings": [finding],
        "payloads_to_test": {finding["id"]: list(payloads)},
        "optimization_retries": {finding["id"]: 1},
        "optimization_attempt_fingerprints": {},
    }
    state.update(overrides)
    return state


def test_same_optimizer_state_routes_to_terminal_debunk_pass():
    from webpent.agents.payload_optimizer.agent import optimization_attempt_fingerprint
    from webpent.graph.builder import NODE_DEVILS_ADVOCATE, route_after_validator

    finding = _finding()
    payloads = ["<probe-a>", "<probe-b>"]
    fingerprint = optimization_attempt_fingerprint(finding, payloads)
    state = _state(
        finding,
        payloads,
        optimization_attempt_fingerprints={finding["id"]: fingerprint},
    )

    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE


def test_changed_payload_set_allows_one_bounded_retry():
    from webpent.agents.payload_optimizer.agent import optimization_attempt_fingerprint
    from webpent.graph.builder import NODE_PAYLOAD_OPTIMIZER, route_after_validator

    finding = _finding()
    previous = optimization_attempt_fingerprint(finding, ["<probe-a>"])
    state = _state(
        finding,
        ["<probe-a>", "<probe-b>"],
        optimization_attempt_fingerprints={finding["id"]: previous},
    )

    assert route_after_validator(state) == NODE_PAYLOAD_OPTIMIZER


def test_changed_validation_status_allows_bounded_reassessment():
    from webpent.agents.payload_optimizer.agent import optimization_attempt_fingerprint
    from webpent.graph.builder import NODE_PAYLOAD_OPTIMIZER, route_after_validator

    finding = _finding()
    previous = optimization_attempt_fingerprint(finding, ["<probe-a>"])
    finding["evidence"] = {
        "validation_failure_reason": "waf_blocked",
        "tool_infra_failure": False,
    }
    state = _state(
        finding,
        ["<probe-a>"],
        optimization_attempt_fingerprints={finding["id"]: previous},
    )

    assert route_after_validator(state) == NODE_PAYLOAD_OPTIMIZER


def test_fingerprint_does_not_depend_on_query_values_or_secret_evidence():
    from webpent.agents.payload_optimizer.agent import optimization_attempt_fingerprint

    first = _finding(
        url="http://user:secret-one@target.example/search?q=secret-one",
        evidence={
            "validation_failure_reason": "tool_no_marker",
            "raw_body": "cookie=super-secret",
        },
    )
    second = _finding(
        id=first["id"],
        url="http://other:secret-two@target.example/search?q=secret-two",
        evidence={
            "validation_failure_reason": "tool_no_marker",
            "raw_body": "cookie=different-secret",
        },
    )
    first_digest = optimization_attempt_fingerprint(first, ["payload-a"])
    second_digest = optimization_attempt_fingerprint(second, ["payload-a"])
    assert first_digest == second_digest


def test_guard_never_promotes_finding():
    from webpent.agents.payload_optimizer.agent import optimization_attempt_fingerprint
    from webpent.graph.builder import route_after_validator

    finding = _finding(confidence="tentative", confidence_level="Pending")
    fingerprint = optimization_attempt_fingerprint(finding, ["payload-a"])
    state = _state(
        finding,
        ["payload-a"],
        optimization_attempt_fingerprints={finding["id"]: fingerprint},
    )

    route_after_validator(state)
    assert state["findings"][0]["confidence"] == "tentative"
    assert state["findings"][0]["confidence_level"] == "Pending"
