from __future__ import annotations

from webpent.dcvu import FixtureProbe, build_default_fixtures


def _probe(fixture, surface_id: str, requester_id: str = "viewer-a") -> FixtureProbe:
    return FixtureProbe(
        surface_id=surface_id,
        requester_id=requester_id,
        object_owner_id="editor-a",
        object_tenant_id="tenant-a",
        requested_role="editor",
    )


def test_default_fixtures_are_distinct_and_local_only() -> None:
    fixtures = build_default_fixtures()
    assert [item.profile.target_id for item in fixtures] == ["fixture-a", "fixture-b", "fixture-c"]
    assert len({item.profile.source_digest for item in fixtures}) == 3
    for fixture in fixtures:
        assert fixture.profile.local_only is True
        assert fixture.profile.disposable is True
        assert fixture.profile.credentials_enabled is False
        assert fixture.profile.mutation_enabled is False


def test_vulnerable_surface_emits_causal_signal_and_clean_surface_denies() -> None:
    fixture_a = build_default_fixtures()[0]
    fixture_b = build_default_fixtures()[1]
    vulnerable = fixture_a.probe(_probe(fixture_a, "fixture-a.object-read"))
    clean = fixture_b.probe(_probe(fixture_b, "fixture-b.role-capability"))
    assert vulnerable.allowed is True
    assert vulnerable.semantic_signal == "causal_unauthorized_access"
    assert vulnerable.impact == "cross-owner read"
    assert clean.allowed is False
    assert clean.semantic_signal == "denied_semantic_access"
    assert clean.impact == "none"


def test_authorized_same_owner_probe_is_a_negative_control() -> None:
    fixture_a = build_default_fixtures()[0]
    control = fixture_a.probe(
        FixtureProbe(
            surface_id="fixture-a.object-read",
            requester_id="editor-a",
            object_owner_id="editor-a",
            object_tenant_id="tenant-a",
            requested_role="editor",
        )
    )
    assert control.allowed is True
    assert control.semantic_signal == "authorized_semantic_access"
    assert control.impact == "none"


def test_fixture_probe_does_not_mutate_surface_inventory() -> None:
    fixture = build_default_fixtures()[1]
    before = fixture.describe_surfaces()
    fixture.probe(_probe(fixture, "fixture-b.tenant-read"))
    after = fixture.describe_surfaces()
    assert before == after
