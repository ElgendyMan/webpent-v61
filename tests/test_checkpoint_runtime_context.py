from webpent.graph.checkpoints import _redact_checkpoint, _redact_value
from webpent.shared.runtime import RuntimeFactory


def _runtime_context():
    return RuntimeFactory.create(
        engagement_id="checkpoint-engagement",
        campaign_id="checkpoint-campaign",
        target_origin="http://example.test",
        raw_scope_entries=["http://example.test"],
        use_default_ledger=False,
    )


def test_live_runtime_context_is_checkpoint_safe_at_all_nesting_levels() -> None:
    context = _runtime_context()

    redacted = _redact_value(
        {
            "runtime_context": context,
            "nested": {"runtime_context": context},
        }
    )
    descriptor = redacted["runtime_context"]
    assert descriptor["engagement_id"] == "checkpoint-engagement"
    assert descriptor["scope_projection"]["raw_entries"] == ["http://example.test"]
    assert isinstance(redacted["nested"]["runtime_context"], dict)
    assert "scope_runtime_handle" not in repr(redacted)

    safe_checkpoint = _redact_checkpoint(
        {
            "channel_values": {"runtime_context": context},
            "metadata": {"runtime_context": context},
        }
    )
    assert isinstance(safe_checkpoint["channel_values"]["runtime_context"], dict)
    assert isinstance(safe_checkpoint["metadata"]["runtime_context"], dict)
    assert safe_checkpoint["metadata"]["runtime_context"]["campaign_id"] == (
        "checkpoint-campaign"
    )
