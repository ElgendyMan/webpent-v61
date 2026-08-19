"""Safe, bounded loaders for operator-supplied scan input files.

The loaders are deliberately independent of Typer so they can be exercised by
unit tests and reused by non-CLI entry points. They never log secret values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2_000_000
MAX_PAYLOADS = 10_000
MAX_PROFILES = 32
MAX_COOKIES = 500
MAX_VALUE_CHARS = 16_384


def _read_bounded(path: Path | str, *, label: str) -> str:
    """Read a UTF-8 file only when it is within the bounded input policy."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise ValueError(f"{label} file does not exist or is not a regular file")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat {label} file: {exc}") from exc
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{label} file exceeds {MAX_FILE_BYTES} bytes")
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {label} file: {exc}") from exc


def _validate_secret_mapping(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        if not key or len(key) > 128 or not isinstance(raw_value, str):
            raise ValueError(f"{label} contains an invalid key or non-string value")
        if len(raw_value) > MAX_VALUE_CHARS:
            raise ValueError(f"{label} contains a value exceeding {MAX_VALUE_CHARS} characters")
        result[key] = raw_value
    return result


def load_creds_file(path: Path | str) -> dict[str, Any]:
    """Load one credential mapping or a bounded set of named profiles.

    Accepted forms are ``{"username": "...", "password": "..."}``, a
    mapping of profile names to such mappings, or ``{"profiles": ...}``.
    Secret values are returned to the caller but are never printed here.
    """
    raw = _read_bounded(path, label="credentials")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"credentials file is not valid JSON: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise ValueError("credentials file must contain a JSON object")
    if "profiles" in payload:
        payload = payload["profiles"]
    if isinstance(payload, dict) and {"username", "password"}.issubset(payload):
        credentials = _validate_secret_mapping(payload, label="credentials")
        if set(credentials) - {"username", "password", "email", "token"}:
            raise ValueError("single credentials object may only contain supported identity fields")
        return credentials
    if not isinstance(payload, dict) or not payload:
        raise ValueError("credentials file must contain at least one profile")
    if len(payload) > MAX_PROFILES:
        raise ValueError(f"credentials file exceeds {MAX_PROFILES} profiles")
    profiles: dict[str, dict[str, str]] = {}
    for raw_name, raw_profile in payload.items():
        name = str(raw_name).strip()
        if not name or len(name) > 128:
            raise ValueError("credentials profile names must be non-empty and short")
        profile = _validate_secret_mapping(raw_profile, label=f"profile '{name}'")
        if "username" not in profile or "password" not in profile:
            raise ValueError(f"profile '{name}' must include username and password")
        profiles[name] = profile
    return profiles


def load_cookie_file(path: Path | str) -> dict[str, str]:
    """Load cookies from a JSON object or Netscape cookie-jar text file."""
    raw = _read_bounded(path, label="cookie")
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"cookie file is not valid JSON: {exc.msg}") from exc
        cookies = _validate_secret_mapping(payload, label="cookies")
    else:
        cookies = {}
        for line_number, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 7:
                raise ValueError(f"invalid Netscape cookie row at line {line_number}")
            name, value = parts[5].strip(), parts[6].strip()
            if not name or len(name) > 256 or len(value) > MAX_VALUE_CHARS:
                raise ValueError(f"invalid cookie at Netscape line {line_number}")
            cookies[name] = value
    if len(cookies) > MAX_COOKIES:
        raise ValueError(f"cookie file exceeds {MAX_COOKIES} cookies")
    return cookies


def load_payload_file(path: Path | str) -> list[str]:
    """Load bounded, non-empty, de-duplicated payload lines from a text file."""
    raw = _read_bounded(path, label="payload")
    payloads: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_VALUE_CHARS:
            raise ValueError(f"payload at line {line_number} exceeds {MAX_VALUE_CHARS} characters")
        if value not in seen:
            seen.add(value)
            payloads.append(value)
        if len(payloads) > MAX_PAYLOADS:
            raise ValueError(f"payload file exceeds {MAX_PAYLOADS} entries")
    return payloads


__all__ = ["load_creds_file", "load_cookie_file", "load_payload_file"]
