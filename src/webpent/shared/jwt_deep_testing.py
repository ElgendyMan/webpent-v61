"""Deterministic, evidence-first JWT deep-testing helpers.

This module intentionally separates offline token analysis from network probing.
It never returns raw JWTs, cookies, keys, or Authorization headers.  Any active
probe remains opt-in at the agent layer and must be explicitly approved by the
engagement state.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Iterable
from typing import Any

_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{2,512}\.[A-Za-z0-9_-]{2,2048}\.[A-Za-z0-9_-]{0,2048}"
    r"(?![A-Za-z0-9_-])"
)

# Small, explicitly bounded candidates.  This is offline verification against
# a token already observed during the engagement, not online password guessing.
DEFAULT_WEAK_SECRET_CANDIDATES: tuple[str, ...] = (
    "secret",
    "password",
    "changeme",
    "change-me",
    "jwt-secret",
    "jwtsecret",
    "mysecret",
    "test",
    "dev",
    "development",
    "webpent",
    "1234567890",
)

_SUPPORTED_HMAC = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _safe_json_segment(value: str) -> dict[str, Any] | None:
    try:
        decoded = _b64url_decode(value)
        parsed = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return None
    return parsed if isinstance(parsed, dict) else None


def token_fingerprint(token: str) -> str:
    """Return a stable non-secret identifier for a captured token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def parse_compact_jwt(token: str) -> dict[str, Any] | None:
    """Parse a compact JWT and return only header/payload metadata.

    The signature bytes and original token are deliberately omitted from the
    returned object.  A malformed or non-compact value returns ``None``.
    """
    if not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header = _safe_json_segment(parts[0])
    payload = _safe_json_segment(parts[1])
    if header is None or payload is None:
        return None
    return {
        "header": header,
        "claims": payload,
        "algorithm": str(header.get("alg") or "").upper(),
        "token_fingerprint": token_fingerprint(token),
        "has_signature": bool(parts[2]),
    }


def extract_candidate_jwts(value: Any, *, max_tokens: int = 100) -> list[str]:
    """Recursively extract bounded JWT candidates from crawl artifacts.

    Only strings matching the compact-JWT shape are returned.  Callers should
    immediately convert them to metadata/fingerprints and must not persist the
    returned values in reports or logs.
    """
    found: list[str] = []
    seen: set[str] = set()

    def visit(item: Any) -> None:
        if len(found) >= max_tokens:
            return
        if isinstance(item, str):
            for match in _JWT_RE.findall(item):
                if match not in seen:
                    seen.add(match)
                    found.append(match)
                    if len(found) >= max_tokens:
                        return
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)
                if len(found) >= max_tokens:
                    return
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)
                if len(found) >= max_tokens:
                    return

    visit(value)
    return found


def _verify_hmac(token: str, secret: str, algorithm: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False
    digest = _SUPPORTED_HMAC.get(algorithm)
    if digest is None:
        return False
    try:
        expected = hmac.new(
            secret.encode("utf-8"), f"{parts[0]}.{parts[1]}".encode("ascii"), digest
        ).digest()
        actual = _b64url_decode(parts[2])
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return False
    return hmac.compare_digest(expected, actual)


def analyze_captured_jwt(
    token: str,
    *,
    weak_secret_candidates: Iterable[str] | None = None,
    public_key_available: bool = False,
) -> dict[str, Any] | None:
    """Analyze a captured token without contacting the target.

    Returned observations are suitable for report state and contain no raw
    credential material.  ``weak_secret_match`` is strong offline evidence;
    ``alg_none_candidate`` and ``key_confusion_candidate`` remain hypotheses
    until a separate, approved endpoint probe confirms acceptance.
    """
    metadata = parse_compact_jwt(token)
    if metadata is None:
        return None

    algorithm = metadata["algorithm"]
    observations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    if algorithm == "NONE":
        observations.append(
            {
                "type": "alg_none_candidate",
                "token_fingerprint": metadata["token_fingerprint"],
                "evidence": (
                    "Captured token declares alg=none; endpoint acceptance is not "
                    "proven offline."
                ),
            }
        )
        gaps.append(
            {
                "type": "jwt_active_acceptance_unverified",
                "reason": (
                    "An explicit approved endpoint probe is required to confirm "
                    "unsigned-token acceptance."
                ),
            }
        )

    candidates = tuple(weak_secret_candidates or DEFAULT_WEAK_SECRET_CANDIDATES)
    if algorithm in _SUPPORTED_HMAC:
        matched = next(
            (candidate for candidate in candidates if _verify_hmac(token, candidate, algorithm)),
            None,
        )
        if matched is not None:
            observations.append(
                {
                    "type": "weak_secret_match",
                    "algorithm": algorithm,
                    "token_fingerprint": metadata["token_fingerprint"],
                    "secret_fingerprint": hashlib.sha256(matched.encode("utf-8")).hexdigest()[:16],
                    "evidence": (
                        "The captured signature verifies offline with a bounded "
                        "common-secret candidate."
                    ),
                }
            )
        else:
            gaps.append(
                {
                    "type": "jwt_secret_strength_unverified",
                    "algorithm": algorithm,
                    "reason": (
                        "The bounded offline candidate set did not match; this is not "
                        "proof of a strong secret."
                    ),
                }
            )

    if algorithm.startswith(("RS", "ES", "PS")) and public_key_available:
        observations.append(
            {
                "type": "key_confusion_candidate",
                "algorithm": algorithm,
                "token_fingerprint": metadata["token_fingerprint"],
                "evidence": (
                    "An asymmetric JWT and a target public key are available; "
                    "algorithm-confusion acceptance still requires an approved probe."
                ),
            }
        )
        gaps.append(
            {
                "type": "jwt_key_confusion_unverified",
                "reason": "No forged-token acceptance is inferred from algorithm metadata alone.",
            }
        )

    # Claims are reduced to safe metadata only; values such as sub/email are
    # intentionally omitted from report-facing observations.
    safe_claim_keys = sorted(
        str(key)
        for key in metadata["claims"]
        if str(key) in {"iss", "aud", "exp", "iat", "nbf", "typ"}
    )
    return {
        "token_fingerprint": metadata["token_fingerprint"],
        "algorithm": algorithm,
        "has_signature": metadata["has_signature"],
        "claim_keys": safe_claim_keys,
        "observations": observations,
        "coverage_gaps": gaps,
    }


def redact_jwt_observation(value: Any) -> Any:
    """Defensively redact token/key-like fields in arbitrary observation data."""
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(
                marker in key_text
                for marker in (
                    "token",
                    "secret",
                    "authorization",
                    "cookie",
                    "private_key",
                    "public_key",
                )
            ):
                if key_text in {"token_fingerprint", "secret_fingerprint"}:
                    clean[str(key)] = str(item)[:32]
                else:
                    clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = redact_jwt_observation(item)
        return clean
    if isinstance(value, list):
        return [redact_jwt_observation(item) for item in value]
    if isinstance(value, str) and _JWT_RE.search(value):
        return "[REDACTED_JWT]"
    return value
