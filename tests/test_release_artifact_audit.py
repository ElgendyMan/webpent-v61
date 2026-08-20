from __future__ import annotations

import json
import zipfile
from pathlib import Path

from scripts.verify_release_artifacts import (
    verify_archive,
    verify_manifest,
    verify_signature,
)


def test_manifest_hashes_are_verified(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("stable\n", encoding="utf-8")
    import hashlib

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"files": {artifact.name: digest}}), encoding="utf-8"
    )
    assert verify_manifest(tmp_path, manifest) == []
    artifact.write_text("tampered\n", encoding="utf-8")
    assert verify_manifest(tmp_path, manifest)


def test_archive_rejects_runtime_and_secret_members(tmp_path: Path) -> None:
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("project/README.md", "safe\n")
        handle.writestr("project/.venv/bin/python", "not included\n")
        handle.writestr("project/private.pem", "-----BEGIN PRIVATE KEY-----\n")
        handle.writestr(
            "project/config.txt", 'password="definitely-not-a-placeholder"\n'
        )
    errors = verify_archive(archive)
    assert any(".venv" in error for error in errors)
    assert any("secret-like" in error or "private.pem" in error for error in errors)


def test_signature_requirement_is_fail_closed(tmp_path: Path) -> None:
    status, errors = verify_signature(None, require_signature=True)
    assert status == "missing"
    assert errors
    signature = tmp_path / "release.sig"
    signature.write_text("detached-signature-placeholder\n", encoding="utf-8")
    status, errors = verify_signature(signature, require_signature=True)
    assert status == "supplied_for_external_verification"
    assert errors == []
