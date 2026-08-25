"""Bounded semantic projections for read-only target adapters.

The adapter receives a response transiently and returns only categorical or
bucketed facts.  No raw body, header, route content, metric name, log line, or
probe value is returned.  A semantic observation is not a finding by itself;
only an explicitly promotable profile may be consumed by the strict replay
runner, and it must still satisfy the independent negative-control contract.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

_PROFILE_CONTRACTS: dict[str, dict[str, Any]] = {
    "juice.directory_listing.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "directory_shape_is_not_a_security_finding_without_resource_oracle",
    },
    "juice.static_resource.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "resource_metadata_requires_class_specific_fingerprint",
    },
    "juice.log_disclosure.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "log_shape_requires_independent_disclosure_oracle",
    },
    "juice.signature_disclosure.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "signature_shape_requires_independent_disclosure_oracle",
    },
    "juice.exposed_metrics.v1": {
        "target_family": "juice_shop",
        "promotable": True,
        "reason": "bounded_prometheus_publication_shape_with_negative_control",
    },
    "juice.policy_resource.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "policy_file_existence_is_not_a_misconfiguration_proof",
    },
    "juice.error_disclosure.v1": {
        "target_family": "juice_shop",
        "promotable": True,
        "reason": "bounded_verbose_error_shape_with_negative_control",
    },
    "juice.public_route.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "public_route_shape_is_not_a_vulnerability_proof",
    },
    "juice.privacy_policy.v1": {
        "target_family": "juice_shop",
        "promotable": False,
        "reason": "privacy_resource_semantics_are_not_an_approved_vulnerability_oracle",
    },
}

_TEXT_CONTENT_TYPES = frozenset({"text/plain", "text/html", "application/json"})
_METRIC_LINE = re.compile(
    r"^(?:#\s+(?:HELP|TYPE)\s+[A-Za-z_:][\w:.-]*(?:\s+[^\n]{0,160})?|"
    r"[A-Za-z_:][\w:.-]*(?:\{[^}]{0,160}\})?\s+"
    r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$"
)
_POLICY_LINE = re.compile(
    r"^(?:Contact|Expires|Policy|Canonical|Acknowledgments):", re.IGNORECASE
)
_LOG_LINE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+/[^ ]*\s+HTTP/\d(?:\.\d)?\b",
    re.IGNORECASE,
)
_SIGNATURE_LINE = re.compile(
    r"^\s*(?:version|signature|error|code|message)\s*:", re.IGNORECASE
)
_STACK_SHAPE = re.compile(
    r"(?:\bat\s+[^\n]{0,160}(?:\.js|\.ts):\d+|/node_modules/|"
    r"Traceback \(most recent call last\))",
    re.IGNORECASE,
)
_DIRECTORY_SHAPE = re.compile(
    r"(?:Index of|Directory listing|Parent Directory|/ftp/)", re.IGNORECASE
)
_SCOREBOARD_SHAPE = re.compile(
    r"(?:score.?board|leaderboard|highest score|points)", re.IGNORECASE
)


def semantic_profile_contract(profile: str) -> Mapping[str, Any] | None:
    """Return a read-only contract copy for a registered semantic profile."""
    contract = _PROFILE_CONTRACTS.get(str(profile or "").strip())
    return dict(contract) if contract else None


def _bucket(value: int, *, high: int = 3) -> int:
    if value <= 0:
        return 0
    if value == 1:
        return 1
    if value <= 4:
        return 2
    return high


def _content_type_family(value: Any) -> str:
    raw = str(value or "").split(";", 1)[0].strip().lower()
    if raw in _TEXT_CONTENT_TYPES:
        return raw
    if raw.startswith("application/"):
        return "application/*"
    if raw.startswith("text/"):
        return "text/*"
    return "other"


def _semantic_match(profile: str, facts: Mapping[str, Any]) -> bool:
    status = int(facts.get("status_code") or 0)
    content_type = str(facts.get("content_type_family") or "")
    if profile == "juice.exposed_metrics.v1":
        return (
            status == 200
            and content_type == "text/plain"
            and int(facts.get("metric_line_count_bucket") or 0) >= 2
        )
    if profile == "juice.error_disclosure.v1":
        return status >= 500 and facts.get("verbose_error_shape") is True
    if profile == "juice.directory_listing.v1":
        return status == 200 and facts.get("directory_shape") is True
    if profile == "juice.log_disclosure.v1":
        return status == 200 and int(facts.get("log_record_count_bucket") or 0) >= 2
    if profile == "juice.signature_disclosure.v1":
        return status == 200 and int(facts.get("signature_field_count_bucket") or 0) >= 2
    if profile == "juice.policy_resource.v1":
        return status == 200 and int(facts.get("policy_directive_count_bucket") or 0) >= 2
    if profile == "juice.public_route.v1":
        return status == 200 and facts.get("scoreboard_shape") is True
    return False


def derive_semantic_observation(
    profile: str,
    *,
    status_code: int | None,
    content_type: Any,
    body: bytes | str | None,
    final_path: str,
) -> dict[str, Any]:
    """Derive bounded semantic facts while discarding the supplied body.

    ``body`` is intentionally not copied into the returned object.  The caller
    should delete its transient response buffer immediately after this call.
    """
    normalized_profile = str(profile or "").strip()
    contract = semantic_profile_contract(normalized_profile)
    if contract is None:
        return {
            "semantic_profile": normalized_profile[:160],
            "semantic_observation_version": "1",
            "semantic_match": False,
            "semantic_oracle_ready": False,
            "semantic_reason": "semantic_profile_not_registered",
        }
    if isinstance(body, bytes):
        text = body[:120_000].decode("utf-8", "replace")
        byte_length = len(body)
    else:
        text = str(body or "")[:120_000]
        byte_length = len(text.encode("utf-8", "replace"))
    lines = text.splitlines()
    metric_count = sum(1 for line in lines if _METRIC_LINE.fullmatch(line.strip()))
    policy_count = sum(1 for line in lines if _POLICY_LINE.match(line.strip()))
    log_count = sum(1 for line in lines if _LOG_LINE.search(line))
    signature_count = sum(1 for line in lines if _SIGNATURE_LINE.match(line))
    facts: dict[str, Any] = {
        "semantic_profile": normalized_profile,
        "semantic_observation_version": "1",
        "content_type_family": _content_type_family(content_type),
        "response_length_bucket": _bucket(byte_length),
        "semantic_path_digest": "sha256:"
        + hashlib.sha256(str(final_path).encode()).hexdigest(),
        "metric_line_count_bucket": _bucket(metric_count),
        "policy_directive_count_bucket": _bucket(policy_count),
        "log_record_count_bucket": _bucket(log_count),
        "signature_field_count_bucket": _bucket(signature_count),
        "directory_shape": bool(_DIRECTORY_SHAPE.search(text)),
        "verbose_error_shape": bool(_STACK_SHAPE.search(text)),
        "scoreboard_shape": bool(_SCOREBOARD_SHAPE.search(text)),
        "status_code": int(status_code or 0),
        "semantic_oracle_ready": bool(contract.get("promotable")),
    }
    facts["semantic_match"] = _semantic_match(normalized_profile, facts)
    facts["semantic_reason"] = (
        "registered_semantic_match"
        if facts["semantic_match"]
        else "registered_semantic_observation"
    )
    return facts


__all__ = ["derive_semantic_observation", "semantic_profile_contract"]
