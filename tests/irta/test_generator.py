from webpent.irta.generator import IndependentTargetGenerator, VulnerabilityClass, generate_target


def test_same_seed_is_reproducible():
    first = generate_target(17)
    second = generate_target(17)
    assert first.canonical_dict() == second.canonical_dict()
    assert first.digest() == second.digest()


def test_different_seeds_change_target_digest_without_changing_contract():
    first = generate_target(17)
    second = generate_target(18)
    assert first.digest() != second.digest()
    assert {route.method for route in first.routes} == {"GET"}
    assert all(route.vulnerability_class for route in first.routes)


def test_target_has_multiple_tenants_identities_and_objects():
    target = IndependentTargetGenerator().generate(3, tenant_count=4, objects_per_tenant=2)
    assert len(target.tenants) == 4
    assert len(target.identities) == 12
    assert len(target.objects) == 8
    assert VulnerabilityClass.IDOR in {route.vulnerability_class for route in target.routes}
    assert VulnerabilityClass.TENANT_ISOLATION in {
        route.vulnerability_class for route in target.routes
    }


def test_invalid_generation_parameters_fail_closed():
    try:
        generate_target(-1)
    except ValueError as exc:
        assert "non-negative" in str(exc)
    else:
        raise AssertionError("negative seeds must be rejected")

    try:
        generate_target(1, tenant_count=1)
    except ValueError as exc:
        assert "two tenants" in str(exc)
    else:
        raise AssertionError("single-tenant targets must be rejected")
