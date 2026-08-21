"""Deterministic oracle and negative-control evaluation for proof slices.

This module evaluates already-collected, redacted observations only. It never
creates requests, starts callbacks, or decides authorization. The executor and
scope gates remain the only components allowed to perform actions.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OracleFamily(str, Enum):
    """Supported proof families with explicit negative-control semantics."""

    IDOR = "idor"
    STORED_XSS = "stored_xss"
    SSRF = "ssrf"
    CSV_SQLI = "csv_sqli"
    REQUEST_SMUGGLING = "request_smuggling"
    CLOUD_STORAGE_EXPOSURE = "cloud_storage_exposure"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    JWT_KEY_CONFUSION = "jwt_key_confusion"


class OracleResult(BaseModel):
    """Redacted deterministic result consumed by proof/reporter layers."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    family: OracleFamily
    causal_signal: bool = False
    negative_control_observed: bool = False
    evidence_complete: bool = False
    status: str = Field(default="inconclusive", max_length=32)
    missing: list[str] = Field(default_factory=list, max_length=8)
    reason: str = Field(default="", max_length=300)

    @property
    def reviewable(self) -> bool:
        return bool(
            self.causal_signal
            and self.negative_control_observed
            and self.evidence_complete
        )


class NegativeControlEngine:
    """Evaluate only the bounded negative-control portion of an observation."""

    @staticmethod
    def observed(family: OracleFamily | str, evidence: Mapping[str, Any]) -> bool:
        value = family.value if isinstance(family, OracleFamily) else str(family)
        if value == OracleFamily.IDOR.value:
            return bool(evidence.get("foreign_denied") or evidence.get("control_denied"))
        if value == OracleFamily.STORED_XSS.value:
            return bool(
                evidence.get("encoded_control_safe")
                and evidence.get("literal_control_safe")
            )
        if value == OracleFamily.SSRF.value:
            return bool(
                evidence.get("negative_callback_absent")
                or evidence.get("control_callback_absent")
            )
        if value == OracleFamily.CSV_SQLI.value:
            return bool(
                evidence.get("negative_control_accepted")
                or evidence.get("negative_control_rejected")
            )
        if value == OracleFamily.REQUEST_SMUGGLING.value:
            return bool(
                evidence.get("control_request_normalized")
                or evidence.get("control_request_rejected")
            )
        if value == OracleFamily.CLOUD_STORAGE_EXPOSURE.value:
            return bool(
                evidence.get("private_object_denied")
                or evidence.get("control_object_denied")
            )
        if value == OracleFamily.SUBDOMAIN_TAKEOVER.value:
            return bool(
                evidence.get("owned_alias_not_claimable")
                or evidence.get("control_alias_not_claimable")
            )
        if value == OracleFamily.JWT_KEY_CONFUSION.value:
            return bool(
                evidence.get("control_token_rejected")
                or evidence.get("symmetric_control_rejected")
            )
        return False


class OracleEngine:
    """Evaluate typed, redacted observations without performing active actions."""

    @staticmethod
    def evaluate(
        family: OracleFamily | str,
        evidence: Mapping[str, Any] | None,
    ) -> OracleResult:
        evidence = evidence if isinstance(evidence, Mapping) else {}
        parsed = family if isinstance(family, OracleFamily) else OracleFamily(str(family))
        missing: list[str] = []
        causal = False

        if parsed is OracleFamily.IDOR:
            causal = bool(
                evidence.get("owner_accessible")
                and evidence.get("foreign_accessible")
            )
            if not evidence.get("owner_accessible"):
                missing.append("owner_baseline")
            if not evidence.get("foreign_accessible"):
                missing.append("foreign_access_observation")
        elif parsed is OracleFamily.STORED_XSS:
            causal = bool(
                evidence.get("execution_marker")
                and evidence.get("fresh_session_replay")
            )
            if not evidence.get("execution_marker"):
                missing.append("browser_execution_marker")
            if not evidence.get("fresh_session_replay"):
                missing.append("fresh_session_replay")
        elif parsed is OracleFamily.SSRF:
            causal = bool(
                evidence.get("callback_received")
                and evidence.get("callback_correlated")
            )
            if not evidence.get("callback_received"):
                missing.append("oob_callback")
            if not evidence.get("callback_correlated"):
                missing.append("callback_correlation")
        elif parsed is OracleFamily.CSV_SQLI:
            causal = bool(
                evidence.get("differential_observed")
                and (
                    evidence.get("sql_error_signature")
                    or evidence.get("timing_differential")
                    or evidence.get("data_flow_effect")
                )
            )
            if not evidence.get("differential_observed"):
                missing.append("controlled_differential")
            if not (
                evidence.get("sql_error_signature")
                or evidence.get("timing_differential")
                or evidence.get("data_flow_effect")
            ):
                missing.append("causal_data_or_sql_signal")
        elif parsed is OracleFamily.REQUEST_SMUGGLING:
            causal = bool(
                evidence.get("parser_desync_observed")
                and evidence.get("smuggled_request_observed")
            )
            if not evidence.get("parser_desync_observed"):
                missing.append("parser_desync_observation")
            if not evidence.get("smuggled_request_observed"):
                missing.append("smuggled_request_observation")
        elif parsed is OracleFamily.CLOUD_STORAGE_EXPOSURE:
            causal = bool(
                evidence.get("unauthenticated_object_read")
                and evidence.get("sensitive_object_observed")
            )
            if not evidence.get("unauthenticated_object_read"):
                missing.append("unauthenticated_object_read")
            if not evidence.get("sensitive_object_observed"):
                missing.append("sensitive_object_observation")
        elif parsed is OracleFamily.SUBDOMAIN_TAKEOVER:
            causal = bool(
                evidence.get("dangling_alias_observed")
                and evidence.get("service_claimable_observed")
            )
            if not evidence.get("dangling_alias_observed"):
                missing.append("dangling_alias_observation")
            if not evidence.get("service_claimable_observed"):
                missing.append("service_claimability_observation")
        elif parsed is OracleFamily.JWT_KEY_CONFUSION:
            causal = bool(
                evidence.get("forged_token_accepted")
                and evidence.get("algorithm_substitution_observed")
            )
            if not evidence.get("forged_token_accepted"):
                missing.append("forged_token_acceptance")
            if not evidence.get("algorithm_substitution_observed"):
                missing.append("algorithm_substitution_observation")

        negative = NegativeControlEngine.observed(parsed, evidence)
        if not negative:
            missing.append("negative_control")
        complete = not missing
        status = "reviewable" if causal and negative and complete else "inconclusive"
        reason = (
            "causal_signal_and_negative_control_observed"
            if status == "reviewable"
            else "proof_requirements_missing"
        )
        return OracleResult(
            family=parsed,
            causal_signal=causal,
            negative_control_observed=negative,
            evidence_complete=complete,
            status=status,
            missing=list(dict.fromkeys(missing)),
            reason=reason,
        )


__all__ = ["NegativeControlEngine", "OracleEngine", "OracleFamily", "OracleResult"]
