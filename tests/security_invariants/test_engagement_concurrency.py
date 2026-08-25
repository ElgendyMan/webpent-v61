from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path

import pytest

pytest.importorskip("bbscout")
from bbscout.signatures import verify_detached_signature
from cryptography.hazmat.primitives import serialization

from tests.test_target_package_v2_hardening import signed_package
from webpent.shared.engagement_factory import EngagementFactory


def _attempt_admission(
    package: dict,
    public_key_bytes: bytes,
    lease_path: str,
    engagement_id: str,
) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    verifier_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    factory = EngagementFactory(
        lease_path,
        signature_verifier=lambda value: verify_detached_signature(
            value,
            trusted_public_keys={"fixture-runtime-key": verifier_key},
        ),
    )
    confirmation = {
        "user_confirmed": True,
        "package_id": package["package_id"],
        "package_sha256": package["integrity"]["content_sha256"],
        "engagement_id": engagement_id,
        "target_url": "http://example.test/app",
    }
    try:
        binding = factory.create_from_package(package, confirmation)
    except Exception as exc:  # assert the redacted contract in the parent
        return ("error", str(exc))
    return ("success", binding.lease_id)


def test_signed_package_admission_is_one_time_across_processes(tmp_path: Path):
    package, private_key = signed_package()
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    lease_path = str(tmp_path / "concurrent-leases.sqlite3")

    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as pool:
        futures = [
            pool.submit(
                _attempt_admission,
                package,
                public_key_bytes,
                lease_path,
                "engagement-concurrent",
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=20) for future in futures]

    assert [kind for kind, _value in results].count("success") == 1
    errors = [value for kind, value in results if kind == "error"]
    assert errors == ["package_already_consumed"]

    factory = EngagementFactory(lease_path)
    binding = factory.get_binding(package["package_id"])
    assert binding is not None
    assert binding["engagement_id"] == "engagement-concurrent"
    assert binding["status"] == "consumed"
