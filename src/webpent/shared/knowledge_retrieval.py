"""Bounded, advisory retrieval for the curated WebPent knowledge pack.

The helper keeps corpus context separate from observed target evidence. Retrieved
text is provenance-labelled, bounded, and remains advisory; callers must still
place it through ``safe_prompt_format`` before an LLM invocation.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from webpent.memory.vectorstore import get_vector_store_manager

logger = logging.getLogger(__name__)

DEFAULT_ADVISORY_TYPES: tuple[str, ...] = (
    "methodology",
    "repository",
    "report",
    "writeup",
    "scenario",
)


def retrieve_knowledge_context(
    query: str,
    *,
    doc_types: Sequence[str] = DEFAULT_ADVISORY_TYPES,
    stack: str | None = None,
    per_type_k: int = 2,
    max_chars: int = 4000,
) -> str:
    """Return bounded, provenance-labelled advisory context from the RAG store.

    Retrieval is fail-closed: empty or invalid queries, unavailable stores, and
    individual filter failures produce an empty result rather than changing
    graph routing or fabricating evidence. The legacy unfiltered call is used
    only when a test or older provider does not accept ``doc_type``.
    """
    if not isinstance(query, str) or not query.strip() or max_chars <= 0:
        return ""

    try:
        manager = get_vector_store_manager()
    except Exception as exc:  # pragma: no cover - defensive provider boundary
        logger.warning("Knowledge manager unavailable: %s", exc)
        return ""

    snippets: list[str] = []
    seen: set[str] = set()
    bounded_k = max(1, min(int(per_type_k), 5))
    for doc_type in tuple(dict.fromkeys(str(value).strip() for value in doc_types)):
        if not doc_type:
            continue
        try:
            results = manager.search_knowledge(
                query,
                k=bounded_k,
                doc_type=doc_type,
                stack=stack,
            )
        except TypeError:
            # Backward-compatible seam for lightweight test doubles and old
            # providers; the real manager supports both filters.
            try:
                results = manager.search_knowledge(query, k=bounded_k)
            except Exception as exc:  # pragma: no cover - defensive boundary
                logger.debug("Legacy knowledge retrieval failed: %s", exc)
                continue
        except Exception as exc:  # pragma: no cover - defensive provider boundary
            logger.debug("Knowledge retrieval failed for type=%s: %s", doc_type, exc)
            continue

        for rank, value in enumerate(results or [], start=1):
            content = str(value).strip()
            if not content or content in seen:
                continue
            seen.add(content)
            snippets.append(f"[RAG type={doc_type} rank={rank}]\n{content}")

    if not snippets:
        logger.debug("Knowledge pack returned no context for query=%r", query)
        return ""

    context = "\n---\n".join(snippets)
    if len(context) > max_chars:
        context = context[:max_chars] + "\n[...RAG context truncated...]"
    logger.info(
        "Retrieved %d bounded knowledge chunk(s) across %d type(s)",
        len(snippets),
        len(tuple(doc_types)),
    )
    return context


__all__ = ["DEFAULT_ADVISORY_TYPES", "retrieve_knowledge_context"]
