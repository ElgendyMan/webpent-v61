from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from bbscout.errors import IntegrityError, PolicyViolationError
from bbscout.integrity import read_json
from bbscout.models import CapabilityProfile
from bbscout.packages import build_target_package, verify_target_package
from bbscout.providers.hackerone_fixture import HackerOneFixtureProvider
from bbscout.scope import compile_scope, decision_for_url
from bbscout.scoring import score_program

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "hackerone"
PROFILE = ROOT / "examples" / "webpent-capabilities.json"


def fixture_provider() -> HackerOneFixtureProvider:
    return HackerOneFixtureProvider(FIXTURES)


def capability_profile() -> CapabilityProfile:
    return CapabilityProfile.from_dict(read_json(PROFILE))


def test_scope_is_ready_and_respects_path_wildcard_and_exclusion() -> None:
    provider = fixture_provider()
    assessment = compile_scope(provider.get_scope("acme-api"))
    assert assessment.status == "ready"
    assert decision_for_url(assessment, "https://api.acme.example/v1/users")[0] is True
    assert decision_for_url(assessment, "https://api.acme.example/v2/users")[0] is False
    assert (
        decision_for_url(assessment, "https://sandbox.acme.example/")[0] is False
    )  # wildcard excludes apex
    assert decision_for_url(assessment, "https://one.sandbox.acme.example/")[0] is True
    assert decision_for_url(assessment, "https://status.acme.example/")[0] is False


def test_stale_and_ambiguous_scope_never_become_ready() -> None:
    provider = fixture_provider()
    assert compile_scope(provider.get_scope("old-assets")).status == "stale"
    assert compile_scope(provider.get_scope("ambiguous-example")).status == "scope_ambiguous"


def test_scoring_blocks_non_ready_scope() -> None:
    provider = fixture_provider()
    profile = capability_profile()
    old = provider.get_program("old-assets")
    result = score_program(old, compile_scope(provider.get_scope("old-assets")), profile)
    assert result.eligibility == "blocked"
    assert result.score is None


def test_ready_scope_and_profile_can_be_scored() -> None:
    provider = fixture_provider()
    profile = capability_profile()
    program = provider.get_program("acme-api")
    result = score_program(program, compile_scope(provider.get_scope("acme-api")), profile)
    assert result.eligibility == "eligible"
    assert result.score is not None
    assert result.confidence in {"medium", "high"}


def test_package_verification_detects_tampering_and_unconfirmed_state() -> None:
    provider = fixture_provider()
    profile = capability_profile()
    program = provider.get_program("acme-api")
    scope = compile_scope(provider.get_scope("acme-api"))
    score = score_program(program, scope, profile)
    package = build_target_package(
        program=program,
        scope=scope,
        score=score,
        profile=profile,
        raw_sources=provider.raw_bundle("acme-api"),
        confirmed_by_user=True,
    )
    assert verify_target_package(package)["valid"] is True

    changed = deepcopy(package)
    changed["program"]["handle"] = "tampered"
    with pytest.raises(IntegrityError):
        verify_target_package(changed)

    with pytest.raises(IntegrityError):
        build_target_package(
            program=program,
            scope=scope,
            score=score,
            profile=profile,
            raw_sources=provider.raw_bundle("acme-api"),
            confirmed_by_user=False,
        )


def test_package_builder_rejects_secret_like_raw_policy_text() -> None:
    provider = fixture_provider()
    profile = capability_profile()
    program = provider.get_program("acme-api")
    scope = compile_scope(provider.get_scope("acme-api"))
    score = score_program(program, scope, profile)
    # Raw sources are evidence only; they must not contain credential-shaped fields.
    raw = provider.raw_bundle("acme-api")
    raw["access_token"] = "do-not-store-me"
    with pytest.raises(IntegrityError):
        build_target_package(
            program=program,
            scope=scope,
            score=score,
            profile=profile,
            raw_sources=raw,
            confirmed_by_user=True,
        )


def test_webpent_ingestor_authorizes_only_matching_urls(tmp_path: Path) -> None:
    from bbscout.webpent_ingestor import TargetPackageIngestor

    provider = fixture_provider()
    profile = capability_profile()
    program = provider.get_program("acme-api")
    scope = compile_scope(provider.get_scope("acme-api"))
    score = score_program(program, scope, profile)
    package = build_target_package(
        program=program,
        scope=scope,
        score=score,
        profile=profile,
        raw_sources=provider.raw_bundle("acme-api"),
        confirmed_by_user=True,
    )
    package_path = tmp_path / "package.json"
    import json
    package_path.write_text(json.dumps(package), encoding="utf-8")

    context = TargetPackageIngestor().ingest(package_path)
    TargetPackageIngestor.authorize_url(context, "https://api.acme.example/v1/projects")
    with pytest.raises(PolicyViolationError):
        TargetPackageIngestor.authorize_url(context, "https://api.acme.example/v2/projects")
