from webpent.irta.generator import AdversarialMutator, MutationKind, generate_target, mutate_target


def test_each_mutation_is_explicit_and_changes_behavior_profile():
    target = generate_target(41)
    for kind in MutationKind:
        mutated = mutate_target(target, kind)
        assert mutated.digest() != target.digest()
        assert mutated.metadata["mutation"] == kind.value
        if kind is MutationKind.PERMISSION_ALIAS:
            assert all(route.required_permission.startswith("alias:") for route in mutated.routes)
        else:
            assert all(route.response_profile != "normal" for route in mutated.routes)


def test_mutation_does_not_modify_base_target():
    target = generate_target(7)
    original_digest = target.digest()
    mutated = AdversarialMutator().mutate(target, MutationKind.PERMISSION_ALIAS)
    assert target.digest() == original_digest
    assert all(route.required_permission.startswith("alias:") for route in mutated.routes)
    assert all(not route.required_permission.startswith("alias:") for route in target.routes)


def test_unknown_mutation_fails_closed():
    target = generate_target(2)
    try:
        AdversarialMutator().mutate(target, "not-a-mutation")
    except ValueError as exc:
        assert "unknown mutation" in str(exc)
    else:
        raise AssertionError("unknown mutations must be rejected")
