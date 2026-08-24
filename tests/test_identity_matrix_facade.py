from webpent.security_models.identity import build_identity_matrix

TARGET = "target-waptlab-local"
ENGAGEMENT = "engagement-001"
ENDPOINT = "http://127.0.0.1:8080/api/orders/42"


def _row(
    identity: str,
    role: str,
    accessible: bool,
    status: int,
    **extra: object,
) -> dict[str, object]:
    return {
        "identity": identity,
        "role": role,
        "object_id": "order-42",
        "endpoint": ENDPOINT,
        "method": "GET",
        "owner_identity": "user-a",
        "accessible": accessible,
        "status_code": status,
        "response_fingerprint": f"fp-{identity}-{status}",
        "evidence_refs": [f"obs-{identity}"],
        "target_backed": True,
        "target_id": TARGET,
        "engagement_id": ENGAGEMENT,
        **extra,
    }


def test_identity_matrix_preserves_roles_and_is_engagement_scoped() -> None:
    matrix = build_identity_matrix(
        [
            _row("anon", "anonymous", False, 401),
            _row("user-a", "user", True, 200),
            _row("premium", "premium_user", True, 200),
            _row("admin", "admin", True, 200),
            _row("svc", "service_account", True, 200),
            _row("other-engagement", "admin", True, 200, engagement_id="other"),
        ],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )

    assert {actor["role"] for actor in matrix["identities"]} == {
        "anonymous",
        "user",
        "premium_user",
        "admin",
        "service_account",
    }
    assert "other-engagement" not in {actor["identity_ref"] for actor in matrix["identities"]}
    assert "cross_target_observation_rejected" in matrix["coverage_gaps"]
    assert matrix["engagement_id"] == ENGAGEMENT
    assert all(row["redacted"] for row in matrix["observations"])


def test_cross_target_observation_is_rejected_without_mixing_state() -> None:
    matrix = build_identity_matrix(
        [
            _row("user-a", "user", True, 200),
            _row("attacker", "user", True, 200, target_id="different-target"),
        ],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )

    assert [row["identity_ref"] for row in matrix["observations"]] == ["user-a"]
    assert "cross_target_observation_rejected" in matrix["coverage_gaps"]
    assert not matrix["comparisons"]


def test_403_expected_200_observed_is_candidate_and_needs_replay() -> None:
    matrix = build_identity_matrix(
        [
            _row("user-a", "user", True, 200, expected_access="allow"),
            _row("user-b", "user", True, 200, expected_access="deny"),
        ],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )

    differentials = [item for item in matrix["comparisons"] if item["access_differential"]]
    assert differentials == []  # both observations are accessible; no false differential

    matrix = build_identity_matrix(
        [
            _row("user-a", "user", True, 200, expected_access="allow"),
            _row("user-b", "user", False, 403, expected_access="deny"),
        ],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )
    differentials = [item for item in matrix["comparisons"] if item["access_differential"]]
    assert differentials
    assert all(
        item["promotion_status"] in {"candidate", "needs_replay", "blocked"}
        for item in differentials
    )
    assert not any(item["promotion_status"] == "confirmed" for item in matrix["comparisons"])
    assert "central_sealed_replayable_bundle_required" not in matrix["coverage_gaps"]


def test_secret_shaped_endpoint_is_rejected() -> None:
    matrix = build_identity_matrix(
        [_row("user-a", "user", True, 200, endpoint="http://127.0.0.1/api?token=secret")],
        target_id=TARGET,
        engagement_id=ENGAGEMENT,
    )
    assert "invalid_identity_observation" in matrix["coverage_gaps"]
    assert matrix["observations"] == []
