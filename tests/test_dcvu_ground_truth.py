from __future__ import annotations

from webpent.dcvu import build_default_fixtures, build_ground_truth_registry


def test_registry_has_one_control_for_each_case() -> None:
    registry = build_ground_truth_registry(build_default_fixtures())
    registry.validate()
    assert len(registry.records) == 18
    assert len(registry.controls) == 18
    assert {item.case.case_id for item in registry.records} == {
        item.case_id for item in registry.controls
    }


def test_registry_contains_positive_and_negative_truth_across_targets() -> None:
    registry = build_ground_truth_registry(build_default_fixtures())
    by_target: dict[str, list[bool]] = {}
    for record in registry.records:
        by_target.setdefault(record.case.target_id, []).append(record.exists)
    assert any(any(values) for values in by_target.values())
    assert any(not all(values) for values in by_target.values())


def test_control_is_same_owner_and_same_tenant() -> None:
    registry = build_ground_truth_registry(build_default_fixtures())
    for record in registry.records:
        control = registry.control_for(record.case.case_id)
        assert control.requester_id == control.owner_id
        assert control.tenant_id == "tenant-a"
        assert control.target_id == record.case.target_id
