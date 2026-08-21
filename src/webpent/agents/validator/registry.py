"""Deterministic validator capability registry.

The registry is intentionally additive: it describes the existing dispatch
contract without extracting or duplicating the validator implementations.
Unknown or structural-only classes remain explicitly unvalidated rather than
being routed through an LLM-only confirmation path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ValidatorCapability:
    """Contract metadata for one vulnerability-class validator."""

    vuln_class: str
    validator_id: str | None
    status: str
    evidence_mode: str


_IMPLEMENTED_VALIDATORS: Final[dict[str, str]] = {
    "xss": "xss",
    "sqli": "sqli",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "rce": "rce",
    "deserialization": "deserialization",
    "lfi": "lfi",
    "rfi": "rfi",
    "ssti": "ssti",
    "xxe": "xxe",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "open_redirect": "open_redirect",
    "info_disclosure": "info_disclosure",
    "idor": "idor",
    "nosql_injection": "nosql_injection",
    "csp": "csp",
    "weak_session": "weak_session",
    "javascript": "javascript",
    "auth_bypass": "auth_bypass",
    "api_issue": "api_issue",
    "cryptography": "cryptography",
    "captcha": "captcha",
    "brute_force": "brute_force",
    # Offline weak-secret verification emits a sealed ProofBundle and a
    # wrong-secret negative control; the central validator revalidates it.
    "jwt_weakness": "jwt_weakness",
}

_OFFLINE_FIXTURE_VALIDATORS: Final[dict[str, str]] = {
    "mass_assignment": "offline-fixture:mass_assignment",
    "request_smuggling": "offline-fixture:request_smuggling",
    "cloud_storage_exposure": "offline-fixture:cloud_storage_exposure",
    "subdomain_takeover": "offline-fixture:subdomain_takeover",
    "jwt_key_confusion": "offline-fixture:jwt_key_confusion",
    "elasticsearch_snapshot_traversal": "offline-fixture:elasticsearch_snapshot_traversal",
    "xslt_injection": "offline-fixture:xslt_injection",
}

_ALL_CLASSES: Final[tuple[str, ...]] = (
    "xss",
    "sqli",
    "ssrf",
    "lfi",
    "rfi",
    "rce",
    "ssti",
    "open_redirect",
    "xxe",
    "csrf",
    "deserialization",
    "path_traversal",
    "command_injection",
    "nosql_injection",
    "info_disclosure",
    "race_condition",
    "idor",
    "auth_bypass",
    "mass_assignment",
    "request_smuggling",
    "brute_force",
    "captcha",
    "weak_session",
    "csp",
    "javascript",
    "cryptography",
    "api_issue",
    "subdomain_takeover",
    "cloud_storage_exposure",
    "jwt_weakness",
    "jwt_key_confusion",
    "elasticsearch_snapshot_traversal",
    "xslt_injection",
    "unknown",
)


def validator_id_for(vuln_class: str) -> str | None:
    """Return the registered validator id, or ``None`` when unsupported."""
    return _IMPLEMENTED_VALIDATORS.get(str(vuln_class))


def capability_for(vuln_class: str) -> ValidatorCapability:
    """Return an explicit capability record for any known or unknown class."""
    vuln_class = str(vuln_class)
    validator_id = validator_id_for(vuln_class)
    if validator_id:
        return ValidatorCapability(
            vuln_class=vuln_class,
            validator_id=validator_id,
            status="tested",
            evidence_mode="deterministic",
        )
    offline_id = _OFFLINE_FIXTURE_VALIDATORS.get(vuln_class)
    if offline_id:
        return ValidatorCapability(
            vuln_class=vuln_class,
            validator_id=offline_id,
            status="offline-fixture",
            evidence_mode="offline-contract",
        )
    return ValidatorCapability(
        vuln_class=vuln_class,
        validator_id=None,
        status="missing-validator",
        evidence_mode="human-review",
    )


def all_capabilities() -> tuple[ValidatorCapability, ...]:
    """Return the stable capability matrix used by coverage reporting."""
    return tuple(capability_for(vuln_class) for vuln_class in _ALL_CLASSES)


def coverage_gap(vuln_class: str) -> dict[str, str | None]:
    """Return a serializable coverage record for a finding class."""
    capability = capability_for(vuln_class)
    return {
        "vuln_class": capability.vuln_class,
        "validator_id": capability.validator_id,
        "status": capability.status,
        "evidence_mode": capability.evidence_mode,
    }


__all__ = [
    "ValidatorCapability",
    "all_capabilities",
    "capability_for",
    "coverage_gap",
    "validator_id_for",
]


# End of registry.py
