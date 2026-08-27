"""Non-networking disposable fixture model for the Option B lab.

This is test infrastructure only.  It never creates an application account,
performs login, calls a reset endpoint, or stores a raw canary/body.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class SyntheticIdentity:
    identity_id: str
    role: str
    credential_material_present: bool = False
    session_material_present: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.identity_id.startswith("test_"):
            errors.append("identity_must_be_opaque_test_id")
        if self.credential_material_present or self.session_material_present:
            errors.append("credential_or_session_material_forbidden")
        return tuple(errors)


@dataclass(frozen=True)
class DisposableCanary:
    canary_id: str
    semantic_label: str
    raw_value_persisted: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.canary_id.startswith("canary_"):
            errors.append("canary_id_must_be_opaque")
        if not self.semantic_label:
            errors.append("canary_semantic_label_required")
        if self.raw_value_persisted:
            errors.append("raw_canary_persistence_forbidden")
        return tuple(errors)


@dataclass(frozen=True)
class DisposableFixture:
    fixture_id: str
    target_id: str
    identities: tuple[SyntheticIdentity, ...]
    canaries: tuple[DisposableCanary, ...]
    application_mutation_performed: bool = False
    application_reset_endpoint_called: bool = False
    raw_values_persisted: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.fixture_id.startswith("fixture_"):
            errors.append("fixture_id_must_be_disposable")
        if not self.target_id:
            errors.append("fixture_target_required")
        if not self.identities or not self.canaries:
            errors.append("fixture_identity_and_canary_required")
        for item in (*self.identities, *self.canaries):
            errors.extend(item.validate())
        if self.application_mutation_performed:
            errors.append("application_mutation_must_remain_false")
        if self.application_reset_endpoint_called:
            errors.append("application_reset_endpoint_must_remain_false")
        if self.raw_values_persisted:
            errors.append("raw_values_persistence_must_remain_false")
        return tuple(errors)

    def state_hash(self) -> str:
        """Hash typed fixture metadata, never raw canary or credential material."""
        payload = {
            "fixture_id": self.fixture_id,
            "target_id": self.target_id,
            "identities": [(item.identity_id, item.role) for item in self.identities],
            "canaries": [(item.canary_id, item.semantic_label) for item in self.canaries],
            "application_mutation_performed": self.application_mutation_performed,
            "application_reset_endpoint_called": self.application_reset_endpoint_called,
            "raw_values_persisted": self.raw_values_persisted,
        }
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def reset_check(self, before_hash: str) -> dict[str, object]:
        after_hash = self.state_hash()
        return {
            "status": "verified"
            if before_hash == after_hash and not self.validate()
            else "blocked",
            "before_state_hash": before_hash,
            "after_state_hash": after_hash,
            "state_hash_equal": before_hash == after_hash,
            "application_reset_endpoint_called": self.application_reset_endpoint_called,
            "application_mutation_performed": self.application_mutation_performed,
            "raw_values_persisted": self.raw_values_persisted,
            "validation_errors": list(self.validate()),
        }


def build_regression_fixture(target_id: str) -> DisposableFixture:
    """Build a local typed fixture for contract regression, not target evidence."""
    fixture = DisposableFixture(
        fixture_id=f"fixture_option_b_{target_id}",
        target_id=target_id,
        identities=(
            SyntheticIdentity("test_subject_a", "owner"),
            SyntheticIdentity("test_subject_b", "requester"),
        ),
        canaries=(
            DisposableCanary("canary_owner_object", "owner-specific semantic marker"),
            DisposableCanary("canary_negative_control", "negative-control semantic marker"),
        ),
    )
    if fixture.validate():
        raise ValueError("regression_fixture_invalid")
    return fixture
