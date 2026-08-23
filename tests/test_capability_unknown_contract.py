from webpent.agents.validator.registry import capability_for


def test_unknown_is_structural_not_missing_validator():
    capability = capability_for("unknown")

    assert capability.validator_id is None
    assert capability.status == "not_applicable"
    assert capability.evidence_mode == "human-review"


def test_real_missing_class_stays_explicitly_missing():
    capability = capability_for("unregistered_future_class")

    assert capability.validator_id is None
    assert capability.status == "missing-validator"
    assert capability.evidence_mode == "human-review"
