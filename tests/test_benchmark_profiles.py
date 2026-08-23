import pytest

from webpent.benchmark import (
    build_offline_target_profile,
    default_offline_target_profiles,
    evaluate,
)
from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationRun,
    build_qualification_matrix,
)


def test_default_profiles_are_offline_fixture_manifests():
    profiles = default_offline_target_profiles()
    assert {profile.profile_id for profile in profiles} == {
        "juice-shop",
        "dvwa",
        "webgoat",
        "wapt-labs",
        "custom",
    }
    for profile in profiles:
        fixture = profile.as_fixture()
        assert fixture.target_ref == f"fixture://{profile.profile_id}"
        assert fixture.scenario["offline_only"] is True
        assert all(case.source == "offline-manifest" for case in fixture.ground_truth)


def test_custom_profile_is_bounded_and_deduplicates_classes():
    profile = build_offline_target_profile(
        "team-fixture",
        "Team fixture",
        ["XSS", "xss", "authorization"],
        scenario={"seed": "fixed"},
    )
    assert profile.vulnerability_classes == ("xss", "authorization")
    assert profile.as_fixture().as_dict()["scenario"]["offline_only"] is True


def test_profile_rejects_unsafe_identifier():
    with pytest.raises(ValueError):
        build_offline_target_profile("https://target.test", "not a target")


def test_qualification_reports_vulnerability_class_coverage():
    ground_truth = [
        GroundTruthCase("case-xss", "xss"),
        GroundTruthCase("case-authz", "authorization"),
    ]
    matrix = build_qualification_matrix(
        ground_truth,
        [
            QualificationRun(
                "run-1",
                "fixture://custom",
                "artifact-1",
                confirmed_case_ids=("case-xss",),
            )
        ],
    )
    summary = matrix.summary()
    assert summary["expected_vulnerability_classes"] == 2
    assert summary["confirmed_vulnerability_classes"] == 1
    assert summary["class_coverage"] == 0.5
    assert summary["live_qualification_proven"] is False


def test_metrics_include_bounded_time_and_llm_token_cost():
    report = evaluate(
        ["xss"],
        ["xss"],
        elapsed_seconds=12.3456789,
        llm_tokens=2048,
    )
    assert report.elapsed_seconds == 12.345679
    assert report.llm_tokens == 2048
    assert report.as_dict()["llm_tokens"] == 2048
