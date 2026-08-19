"""Immutable, replay-oriented proof bundle primitives.

The bundle stores only redacted references and deterministic digests.  It is a
proof artifact contract, not a finding promoter: callers still need a
validator result before claiming confirmation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive, sha256_text


class CustodyEvent(BaseModel):
    """One append-only custody event for a proof bundle."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    actor: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = Field(default="", max_length=240)

    @field_validator("actor", "action", "note", mode="before")
    @classmethod
    def _redact_text(cls, value: Any) -> str:
        clean, _ = redact_sensitive(str(value or ""))
        return clean


class ProofBundle(BaseModel):
    """Frozen proof metadata with explicit sealing and deterministic replay."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    bundle_id: str = Field(default_factory=lambda: f"proof_bundle_{uuid4().hex}", min_length=1)
    engagement_id: str = Field(min_length=1, max_length=160)
    finding_id: str = Field(min_length=1, max_length=160)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    evidence_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    negative_control_digest: str | None = None
    chain_of_custody: tuple[CustodyEvent, ...] = Field(default_factory=tuple, max_length=64)
    sealed: bool = False
    seal_digest: str | None = None

    @field_validator("engagement_id", "finding_id", "evidence_refs", mode="before")
    @classmethod
    def _redact_identity_or_refs(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    @field_validator("evidence_digests", "negative_control_digest", "seal_digest", mode="before")
    @classmethod
    def _validate_digest_text(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (tuple, list)):
            for item in value:
                cls._validate_digest_text(item)
            return value
        text = str(value)
        if not text.startswith("sha256:") or len(text) != 71:
            raise ValueError("digest must be sha256:<64 hex characters>")
        int(text[7:], 16)
        return text

    def _seal_payload(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "engagement_id": self.engagement_id,
            "finding_id": self.finding_id,
            "evidence_refs": list(self.evidence_refs),
            "evidence_digests": list(self.evidence_digests),
            "negative_control_digest": self.negative_control_digest,
            "chain_of_custody": [event.model_dump(mode="json") for event in self.chain_of_custody],
        }

    def seal(self, *, actor: str = "system") -> ProofBundle:
        """Return a new sealed bundle; the existing instance is never mutated."""
        if self.sealed:
            return self
        event = CustodyEvent(actor=actor, action="seal")
        with_event = self.model_copy(update={"chain_of_custody": (*self.chain_of_custody, event)})
        digest = f"sha256:{sha256_text(with_event._seal_payload())}"
        return with_event.model_copy(update={"sealed": True, "seal_digest": digest})

    def verify_seal(self) -> bool:
        """Verify that a sealed bundle has not been altered."""
        if not self.sealed or not self.seal_digest:
            return False
        expected = f"sha256:{sha256_text(self._seal_payload())}"
        return expected == self.seal_digest

    def replay(
        self,
        evidence_payloads: tuple[Any, ...] | list[Any],
        negative_control: Any = None,
    ) -> bool:
        """Verify supplied deterministic evidence payloads against stored digests."""
        if not self.sealed or not self.verify_seal():
            return False
        digests = tuple(
            f"sha256:{sha256_text(redact_sensitive(item)[0])}"
            for item in evidence_payloads
        )
        if digests != self.evidence_digests:
            return False
        if self.negative_control_digest is None:
            return negative_control is None
        if negative_control is None:
            return False
        actual = f"sha256:{sha256_text(redact_sensitive(negative_control)[0])}"
        return actual == self.negative_control_digest

    def append_custody(self, *, actor: str, action: str, note: str = "") -> ProofBundle:
        """Return a new unsealed bundle with one custody event."""
        if self.sealed:
            raise ValueError("sealed_proof_bundle_is_immutable")
        event = CustodyEvent(actor=actor, action=action, note=note)
        return self.model_copy(update={"chain_of_custody": (*self.chain_of_custody, event)})


def build_proof_bundle(
    *,
    engagement_id: str,
    finding_id: str,
    evidence: tuple[Any, ...] | list[Any] = (),
    evidence_refs: tuple[str, ...] | list[str] = (),
    negative_control: Any = None,
) -> ProofBundle:
    """Build a redaction-safe bundle from deterministic evidence payloads."""
    clean_evidence = tuple(redact_sensitive(item)[0] for item in evidence)
    negative_digest = (
        f"sha256:{sha256_text(redact_sensitive(negative_control)[0])}"
        if negative_control is not None
        else None
    )
    return ProofBundle(
        engagement_id=engagement_id,
        finding_id=finding_id,
        evidence_refs=tuple(str(ref)[:500] for ref in evidence_refs)[:32],
        evidence_digests=tuple(f"sha256:{sha256_text(item)}" for item in clean_evidence)[:32],
        negative_control_digest=negative_digest,
    )


def validate_proof_bundle(
    value: Any,
    *,
    require_negative_control: bool = False,
) -> bool:
    """Return whether a serialized or live bundle is sealed and structurally usable."""
    try:
        bundle = value if isinstance(value, ProofBundle) else ProofBundle.model_validate(value)
    except Exception:
        return False
    if not bundle.verify_seal() or not bundle.evidence_digests:
        return False
    if not bundle.evidence_refs:
        return False
    return not require_negative_control or bundle.negative_control_digest is not None


__all__ = [
    "CustodyEvent",
    "ProofBundle",
    "build_proof_bundle",
    "validate_proof_bundle",
]
