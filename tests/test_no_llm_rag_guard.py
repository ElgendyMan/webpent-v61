from __future__ import annotations

import pytest

from webpent.memory.embeddings import (
    get_embeddings,
    is_rag_enabled,
    rag_enabled_override,
)
from webpent.memory.vectorstore import (
    _DEFAULT_LESSONS_COLLECTION,
    VectorStoreManager,
)


def test_rag_override_blocks_model_load_and_cached_store(monkeypatch):
    manager = VectorStoreManager(persist_path="/tmp/webpent-test-chroma")
    sentinel_store = object()
    manager._lessons_store = sentinel_store

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("embedding implementation must not be imported/called")

    monkeypatch.setattr(
        "webpent.memory.embeddings.HuggingFaceEmbeddings",
        fail_if_called,
        raising=False,
    )

    with rag_enabled_override(False):
        assert is_rag_enabled() is False
        assert manager._get_store(_DEFAULT_LESSONS_COLLECTION) is None
        with pytest.raises(RuntimeError, match="RAG disabled"):
            get_embeddings()

    assert is_rag_enabled() is True
    assert manager._lessons_store is sentinel_store


def test_rag_override_is_nested_and_restored():
    with rag_enabled_override(False):
        assert is_rag_enabled() is False
        with rag_enabled_override(True):
            assert is_rag_enabled() is True
        assert is_rag_enabled() is False
    assert is_rag_enabled() is True
