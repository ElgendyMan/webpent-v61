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
