from __future__ import annotations

from webpent.models.memory import MemoryKind
from webpent.shared.security_reasoning_memory import SecurityReasoningMemory


def test_memory_is_isolated_by_engagement_and_target() -> None:
    first = SecurityReasoningMemory(engagement_id="eng", target_id="target-a")
    second = SecurityReasoningMemory(engagement_id="eng", target_id="target-b")

    record = first.remember(
        category=MemoryKind.TARGET_FACT,
        content="owner relation observed; Authorization: Bearer secret-token must not persist",
        source_ref="fixture:observation",
        evidence_refs=["evidence:owner"],
        relevance=0.8,
    )

    assert record is not None
    assert record.target_scope == "eng:target-a"
    assert "secret-token" not in record.content
    assert "authorization" not in record.provenance.source_ref.lower()
    assert first.retrieve("owner relation").items
    assert not second.retrieve("owner relation").items


def test_memory_ids_are_stable_and_records_are_advisory() -> None:
    kwargs = {
        "category": "experience_lesson",
        "content": "negative control separated candidate semantics",
        "source_ref": "run:1",
        "evidence_refs": ["evidence:control"],
    }
    first = SecurityReasoningMemory(engagement_id="eng", target_id="target")
    second = SecurityReasoningMemory(engagement_id="eng", target_id="target")

    first_record = first.remember(**kwargs)
    second_record = second.remember(**kwargs)

    assert first_record is not None and second_record is not None
    assert first_record.id == second_record.id
    assert first.summary()["isolated"] is True
    assert first.summary()["authoritative"] is False
    assert first.summary()["execution_capability"] is False
    assert first.record_feedback(first_record.id, "accepted") is not None
