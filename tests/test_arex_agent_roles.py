from webpent.agents.team import ROLE_SPECS, get_role_spec, team_manifest, validate_role_artifact

AREX_ROLES = {
    "arex_recon_researcher",
    "arex_authorization_researcher",
    "arex_business_logic_researcher",
    "arex_evidence_reviewer",
    "arex_planner",
}


def test_arex_roles_are_registered_with_advisory_only_boundaries():
    registered = {spec.role for spec in ROLE_SPECS}

    assert registered >= AREX_ROLES
    for role in AREX_ROLES:
        spec = get_role_spec(role)
        assert spec is not None
        assert spec.advisory_only is True
        assert spec.can_execute is False
        assert spec.can_create_findings is False
        assert spec.can_override_oracle is False


def test_arex_role_artifacts_accept_declared_advice_only():
    assert validate_role_artifact(
        "arex_planner",
        {"task_proposal": {"task_id": "task-001", "route": "observation"}},
    )
    assert validate_role_artifact(
        "arex_evidence_reviewer",
        {"evidence_review": {"proof_complete": False}},
    )
    assert validate_role_artifact(
        "arex_authorization_researcher",
        {"negative_control_plan": {"required": True}},
    )


def test_role_artifact_validator_rejects_authority_shaped_outputs():
    for role in AREX_ROLES:
        assert not validate_role_artifact(role, {"finding": {"title": "not allowed"}})
        assert not validate_role_artifact(role, {"execute": True})
        assert not validate_role_artifact(role, {"policy_override": True})
        assert not validate_role_artifact(role, {"oracle_override": True})


def test_team_manifest_is_json_safe_and_preserves_arex_flags():
    manifest = {item["role"]: item for item in team_manifest()}

    for role in AREX_ROLES:
        entry = manifest[role]
        assert entry["advisory_only"] is True
        assert entry["can_execute"] is False
        assert entry["can_create_findings"] is False
        assert entry["can_override_oracle"] is False
