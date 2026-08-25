"""Detached Ed25519 signatures for Target Package v2.

Private keys are accepted only at runtime.  Nothing in this module generates,
stores, or embeds a trusted key.  Verification is fail-closed when the key id
is absent from the caller-supplied trust map.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import IntegrityError
from .integrity import package_digest

_SIGNATURE_PREFIX = b"bbscout-target-package-v2:"


def _private_key(value: Any) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        raise IntegrityError("مفتاح Ed25519 الخاص غير صالح.")
    raw = bytes(value)
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    try:
        loaded = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise IntegrityError("مفتاح Ed25519 الخاص يجب أن يكون raw 32-byte أو PEM.") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise IntegrityError("المفتاح الخاص ليس Ed25519.")
    return loaded


def _public_key(value: Any) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        raise IntegrityError("مفتاح Ed25519 العام غير صالح.")
    raw = bytes(value)
    if len(raw) == 32:
        return Ed25519PublicKey.from_public_bytes(raw)
    try:
        loaded = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise IntegrityError("مفتاح Ed25519 العام يجب أن يكون raw 32-byte أو PEM.") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise IntegrityError("المفتاح العام ليس Ed25519.")
    return loaded


def signature_message(package: Mapping[str, Any], content_sha256: str | None = None) -> bytes:
    """Build the domain-separated message authenticated by the detached sig."""
    digest = str(content_sha256 or package.get("integrity", {}).get("content_sha256") or "")
    package_id = str(package.get("package_id") or "")
    if len(digest) != 64 or not package_id:
        raise IntegrityError("لا يمكن توقيع package identity/digest ناقص.")
    return _SIGNATURE_PREFIX + digest.encode("ascii") + b":" + package_id.encode("utf-8")


def sign_target_package(
    package: Mapping[str, Any],
    *,
    private_key: Any,
    key_id: str,
) -> dict[str, Any]:
    """Return a signed copy; the caller retains control of the private key."""
    if not str(key_id).strip():
        raise IntegrityError("key_id مطلوب لتوقيع Target Package.")
    signed = deepcopy(dict(package))
    integrity = dict(signed.get("integrity") or {})
    integrity.update(
        {
            "detached_signature": None,
            "signature_state": "verified",
            "key_id": str(key_id),
            "signature_algorithm": "Ed25519",
        }
    )
    signed["integrity"] = integrity
    content_sha256 = package_digest(signed)
    integrity["content_sha256"] = content_sha256
    signature = _private_key(private_key).sign(signature_message(signed, content_sha256))
    integrity["detached_signature"] = base64.b64encode(signature).decode("ascii")
    signed["integrity"] = integrity
    return signed


def verify_detached_signature(
    package: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, Any],
) -> None:
    """Verify a package signature using only caller-provided trusted keys."""
    integrity = package.get("integrity")
    if not isinstance(integrity, Mapping):
        raise IntegrityError("integrity section مفقودة.")
    if integrity.get("signature_state") != "verified":
        raise IntegrityError("Target Package غير موقعة بتوقيع verified.")
    if integrity.get("signature_algorithm") != "Ed25519":
        raise IntegrityError("خوارزمية التوقيع غير مدعومة.")
    key_id = str(integrity.get("key_id") or "")
    if not key_id or key_id not in trusted_public_keys:
        raise IntegrityError("مفتاح التوقيع غير موجود في trust map.")
    encoded = integrity.get("detached_signature")
    if not isinstance(encoded, str) or not encoded:
        raise IntegrityError("detached signature مفقود.")
    try:
        signature = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise IntegrityError("detached signature ليس base64 صالحًا.") from exc
    expected_digest = package_digest(dict(package))
    if str(integrity.get("content_sha256") or "") != expected_digest:
        raise IntegrityError("فشل canonical package digest قبل التوقيع.")
    try:
        _public_key(trusted_public_keys[key_id]).verify(
            signature,
            signature_message(package, expected_digest),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise IntegrityError("فشل تحقق detached Ed25519 signature.") from exc


__all__ = ["sign_target_package", "signature_message", "verify_detached_signature"]
