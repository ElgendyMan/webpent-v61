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


def test_learning_support_is_scoped_and_advisory() -> None:
    first = SecurityReasoningMemory(engagement_id="eng", target_id="target-a")
    second = SecurityReasoningMemory(engagement_id="eng", target_id="target-b")

    lesson = first.learn_from_outcome(
        hypothesis_id="h-id-or-1",
        outcome="blocked",
        rationale="precondition missing; Authorization: Bearer secret-token",
        evidence_refs=["evidence:control"],
        relevance=0.7,
    )

    assert lesson is not None
    assert lesson.kind is MemoryKind.EXPERIENCE_LESSON
    assert lesson.target_scope == "eng:target-a"
    assert lesson.metadata["advisory_only"] is True
    assert "secret-token" not in lesson.content
    assert first.retrieve_learning("precondition missing").items
    assert not second.retrieve_learning("precondition missing").items
    assert first.feedback_records[-1].status == "needs_more_evidence"
    assert first.summary()["authoritative"] is False
    assert first.summary()["execution_capability"] is False


def test_learning_support_rejects_unknown_outcome() -> None:
    memory = SecurityReasoningMemory(engagement_id="eng", target_id="target")

    try:
        memory.learn_from_outcome(
            hypothesis_id="h-1",
            outcome="confirmed_without_proof",
            rationale="must fail closed",
        )
    except ValueError as exc:
        assert str(exc) == "unsupported_learning_outcome"
    else:
        raise AssertionError("unsupported learning outcome was accepted")


def test_learning_support_ids_are_deterministic() -> None:
    kwargs = {
        "hypothesis_id": "h-idor-2",
        "outcome": "rejected",
        "rationale": "negative control did not differ",
        "evidence_refs": ["evidence:negative"],
    }
    first = SecurityReasoningMemory(engagement_id="eng", target_id="target")
    second = SecurityReasoningMemory(engagement_id="eng", target_id="target")

    first_record = first.learn_from_outcome(**kwargs)
    second_record = second.learn_from_outcome(**kwargs)

    assert first_record is not None and second_record is not None
    assert first_record.id == second_record.id
    assert first.feedback_records[-1].status == "rejected"
    assert second.feedback_records[-1].status == "rejected"
