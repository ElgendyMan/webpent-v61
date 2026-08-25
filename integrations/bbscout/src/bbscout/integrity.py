"""Canonical JSON, integrity digests, and conservative secret scanning."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from .errors import IntegrityError

SECRET_KEYS = re.compile(
    r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|authorization|password|cookie|session|otp|client[_-]?secret)"
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(?:sk|pk|ghp|xoxb|h1)_[a-z0-9_-]{12,}"),
]
# These are package container names, not credential field names. Their children are
# still traversed and keys such as access_token/cookie/password remain prohibited.
SAFE_CONTAINER_KEYS = {"authorization", "integrity", "redaction"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_secret_paths(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SECRET_KEYS.search(str(key)) and str(key).lower() not in SAFE_CONTAINER_KEYS:
                findings.append(child_path)
            findings.extend(find_secret_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_secret_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str) and any(
        pattern.search(value) for pattern in SECRET_VALUE_PATTERNS
    ):
        findings.append(path)
    return findings


def redact(value: Any) -> Any:
    """Return a copy with potentially secret values replaced, preserving shape."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, child in value.items():
            output[key] = "[REDACTED]" if SECRET_KEYS.search(str(key)) else redact(child)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def package_digest(package: dict[str, Any]) -> str:
    unsigned = deepcopy(package)
    integrity = dict(unsigned.get("integrity", {}))
    integrity.pop("content_sha256", None)
    integrity.pop("detached_signature", None)
    unsigned["integrity"] = integrity
    return sha256_json(unsigned)


def verify_package_digest(package: dict[str, Any]) -> None:
    expected = package.get("integrity", {}).get("content_sha256")
    if not expected:
        raise IntegrityError("الحزمة لا تحتوي على content_sha256.")
    actual = package_digest(package)
    if actual != expected:
        raise IntegrityError("فشل التحقق: محتوى الحزمة تغيّر بعد بنائها.")
    secret_paths = find_secret_paths(package)
    allowed = {"$.integrity.content_sha256", "$.source.source_response_sha256"}
    forbidden = [item for item in secret_paths if item not in allowed]
    if forbidden:
        raise IntegrityError("فشل فحص الأسرار: " + ", ".join(forbidden))


def read_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
