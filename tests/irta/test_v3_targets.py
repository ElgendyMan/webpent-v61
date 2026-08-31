from fastapi.testclient import TestClient

from webpent.irta.v3 import build_independent_targets


def test_factory_builds_five_independent_targets() -> None:
    targets = build_independent_targets()
    assert len(targets) == 5
    assert len({target.target_id for target in targets}) == 5
    assert len({target.runtime_digest for target in targets}) == 5
    assert all(target.app.openapi for target in targets)


def test_detector_facing_runtime_has_no_ground_truth_field() -> None:
    target = build_independent_targets()[0]
    assert not hasattr(target, "ground_truth")
    assert not hasattr(target, "vulnerabilities")
    assert not hasattr(target, "expected_answers")


def test_target_exposes_real_http_routes_with_synthetic_context() -> None:
    target = build_independent_targets()[0]
    client = TestClient(target.app)
    assert client.get(f"{target.base_path}/health").json()["status"] == "ok"
    response = client.get(
        f"{target.base_path}/api/profile",
        headers={"X-Actor": "user-1", "X-Tenant": "blue"},
    )
    assert response.status_code == 200
    assert response.json()["tenant"] == "blue"


def test_cross_tenant_object_access_is_denied_for_non_admin() -> None:
    target = build_independent_targets()[0]
    client = TestClient(target.app)
    response = client.get(
        f"{target.base_path}/api/objects/alpha-1",
        headers={"X-Actor": "user-2", "X-Tenant": "red"},
    )
    assert response.status_code == 403


def test_target_instances_do_not_share_mutable_application_state() -> None:
    first, second = build_independent_targets()[:2]
    assert first.app is not second.app
    assert first.base_path != second.base_path
    assert first.runtime_digest != second.runtime_digest
