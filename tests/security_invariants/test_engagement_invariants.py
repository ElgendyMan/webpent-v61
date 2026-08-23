import pytest
from bbscout.signatures import verify_detached_signature

from tests.test_target_package_v2_hardening import signed_package
from webpent.shared.engagement_factory import EngagementAdmissionError, EngagementFactory


def _factory(tmp_path, private_key):
    return EngagementFactory(
        tmp_path / "leases.sqlite3",
        signature_verifier=lambda value: verify_detached_signature(
            value,
            trusted_public_keys={"fixture-runtime-key": private_key.public_key()},
        ),
    )


def _confirmation(package, engagement_id):
    return {
        "user_confirmed": True,
        "package_id": package["package_id"],
        "package_sha256": package["integrity"]["content_sha256"],
        "engagement_id": engagement_id,
        "target_url": "http://example.test/app",
    }


def test_package_consumption_is_one_time_and_restore_is_exact(tmp_path):
    package, private_key = signed_package()
    factory = _factory(tmp_path, private_key)
    confirmation = _confirmation(package, "engagement-one")

    first = factory.create_from_package(package, confirmation)
    restored = factory.restore_existing_binding(package, confirmation)

    assert restored.as_dict() == first.as_dict()
    with pytest.raises(EngagementAdmissionError, match="package_already_consumed"):
        factory.create_from_package(package, confirmation)


def test_same_package_cannot_bind_to_a_second_engagement(tmp_path):
    package, private_key = signed_package()
    factory = _factory(tmp_path, private_key)
    factory.create_from_package(package, _confirmation(package, "engagement-one"))

    with pytest.raises(EngagementAdmissionError, match="package_already_consumed"):
        factory.create_from_package(package, _confirmation(package, "engagement-two"))


def test_restore_rejects_projection_tampering(tmp_path):
    package, private_key = signed_package()
    factory = _factory(tmp_path, private_key)
    binding = factory.create_from_package(package, _confirmation(package, "engagement-one"))
    projection = binding.as_dict()
    projection["scope_digest"] = "sha256:" + "0" * 64

    with pytest.raises(EngagementAdmissionError, match="package_binding_continuity_mismatch"):
        factory.restore_binding_projection(projection)


def test_restore_rejects_unknown_or_unconsumed_status(tmp_path):
    package, private_key = signed_package()
    factory = _factory(tmp_path, private_key)
    binding = factory.create_from_package(package, _confirmation(package, "engagement-one"))
    projection = binding.as_dict()
    projection["target_package_status"] = "unknown"

    with pytest.raises(EngagementAdmissionError, match="package_binding_status_mismatch"):
        factory.restore_binding_projection(projection)
