from __future__ import annotations

from webpent.shared import knowledge_retrieval
from webpent.shared.skill_selector import get_skill_reference, select_skills


class _PayloadManager:
    def search_knowledge(self, query, *, k, doc_type, stack=None):
        assert "xss" in query.lower()
        assert doc_type == "payload"
        return ["<svg/onload=PAYLOAD_CANARY>"]


def test_payload_generation_skill_returns_local_payload_reference(monkeypatch):
    monkeypatch.setattr(knowledge_retrieval, "get_vector_store_manager", lambda: _PayloadManager())

    matched_skills = select_skills("payload_generation", "xss")
    assert matched_skills

    reference = get_skill_reference(matched_skills[0], "finding-xss-1")

    assert reference
    assert "PAYLOAD_CANARY" in reference
