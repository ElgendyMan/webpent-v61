#!/usr/bin/env python3
"""Offline release-artifact verification for WebPent.

This module never contacts a target, starts a service, or executes an external
scanner. Signature verification is deliberately optional and fails closed when
``--require-signature`` is requested without an operator-supplied signature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from collections.abc import Iterable
from pathlib import Path

FORBIDDEN_MEMBER_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "chroma_db",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db"}
FORBIDDEN_NAMES = {"cookies.json", "credentials.json", "secrets.json"}
SECRET_PATTERNS = (
    re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    re.compile(r"(?:sk|rk)-[A-Za-z0-9]{20,}"),
    re.compile(
        r"password\s*[:=]\s*[\"'][^\"']{12,}[\"']", re.IGNORECASE
    ),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest(repo: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]
    for relative, expected in manifest.get("files", {}).items():
        path = repo / relative
        if not path.is_file():
            errors.append(f"manifest file missing: {relative}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"manifest hash mismatch: {relative}")
    return errors


def _member_is_forbidden(name: str) -> bool:
    path = Path(name)
    if any(part in FORBIDDEN_MEMBER_PARTS for part in path.parts):
        return True
    if path.name in FORBIDDEN_NAMES:
        return True
    return path.suffix.lower() in FORBIDDEN_SUFFIXES


def _bytes_have_secret_pattern(data: bytes) -> bool:
    if len(data) > 2 * 1024 * 1024 or b"\x00" in data:
        return False
    text = data.decode("utf-8", errors="ignore")
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def verify_archive(archive_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(archive_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                errors.append(f"corrupt archive member: {bad_member}")
            for info in archive.infolist():
                if _member_is_forbidden(info.filename):
                    errors.append(f"forbidden archive member: {info.filename}")
                    continue
                try:
                    data = archive.read(info)
                except OSError as exc:
                    errors.append(f"cannot read archive member {info.filename}: {exc}")
                    continue
                if _bytes_have_secret_pattern(data):
                    errors.append(f"secret-like content in archive member: {info.filename}")
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"archive unreadable: {exc}")
    return errors


def verify_signature(signature_path: Path | None, require_signature: bool) -> tuple[str, list[str]]:
    if signature_path is None:
        if require_signature:
            return "missing", ["operator signature required but no detached signature was supplied"]
        return "operator_key_required", []
    if not signature_path.is_file():
        return "missing", [f"signature file missing: {signature_path}"]
    if signature_path.stat().st_size == 0:
        return "invalid", ["signature file is empty"]
    return "supplied_for_external_verification", []


def verify_paths(paths: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"required path missing: {path}")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors = verify_paths((args.repo, args.manifest))
    if not errors:
        errors.extend(verify_manifest(args.repo, args.manifest))
    if args.archive:
        errors.extend(verify_archive(args.archive))
    signature_status, signature_errors = verify_signature(
        args.signature, args.require_signature
    )
    errors.extend(signature_errors)
    result = {
        "offline_only": True,
        "target_contacted": False,
        "signature_status": signature_status,
        "errors": errors,
        "passed": not errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "main",
    "sha256_file",
    "verify_archive",
    "verify_manifest",
]


# The public API intentionally remains small; callers should use the CLI for
# release verification so the offline and signature boundaries stay visible.


def _public_api_marker() -> None:
    return None


_ = _public_api_marker


# Keep this module importable by the repository's script-level checks without
# changing the application runtime package.


__version__ = "1"


# End of file.
