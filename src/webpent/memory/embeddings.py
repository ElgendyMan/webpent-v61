# src/webpent/memory/embeddings.py
"""webpent.memory.embeddings

Embedding model factory for the WebPent Framework V2 RAG system.

Provides a single entry point, :func:`get_embeddings`, which returns a
free, local, offline embedding model suitable for semantic search over
lessons learned and hypotheses.

Model choice:
    ``all-MiniLM-L6-v2`` from SentenceTransformers is used because:
      * **Free & local** — no API key, no network calls, no per-token
        cost. Ideal for an offline security framework.
      * **Fast** — 384-dimensional embeddings, ~0.1s per sentence on
        CPU.
      * **Good quality** — consistently ranks near the top of the
        MTEB leaderboard for its size class.
      * **Small** — ~80MB on disk, downloaded once and cached.

    The model is downloaded automatically by SentenceTransformers on
    first use and cached under ``~/.cache/huggingface/``. Subsequent
    runs load it from disk with no network access.

Resilience:
    If the model cannot be loaded (e.g. first-run download failure on
    an air-gapped machine), :func:`get_embeddings` raises a clear
    ``RuntimeError`` with installation guidance rather than silently
    returning a broken object.
"""

from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

# The SentenceTransformers model identifier. ``all-MiniLM-L6-v2`` is
# the canonical choice for the framework — changing it requires
# re-indexing the Chroma collection, so it is hard-coded here to
# prevent accidental model drift between runs.
_DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def get_embeddings():
    """Return a cached :class:`Embeddings` instance for the RAG system.

    The function is memoized via :func:`lru_cache` so the
    SentenceTransformers model is loaded only once per process. The
    model download (~80MB) happens on first invocation; subsequent
    calls return the cached object instantly.

    V10 P0-2 (RCA follow-up): respects two new settings switches —
    ``DISABLE_RAG`` and ``EMBEDDINGS_OFFLINE``. When ``DISABLE_RAG=true``,
    this function raises ``RuntimeError`` immediately so callers skip
    RAG entirely (no model load, no network). When
    ``EMBEDDINGS_OFFLINE=true``, the HuggingFaceEmbeddings constructor
    is invoked with ``local_files_only=True`` so it loads from the
    cache only — if the model is not cached, the RuntimeError surfaces
    immediately instead of stalling on a multi-minute network download.

    Returns:
        A LangChain :class:`Embeddings` instance backed by
        ``HuggingFaceEmbeddings`` using ``all-MiniLM-L6-v2``.

    Raises:
        RuntimeError: If the embedding model cannot be loaded (e.g.
            missing ``sentence-transformers`` package, model download
            failure, corrupted cache, or DISABLE_RAG/EMBEDDINGS_OFFLINE
            set and model not cached). The error message includes
            installation guidance.
    """
    # V10 P0-2: check the RAG-disable switch FIRST — if the operator
    # explicitly disabled RAG, do NOT attempt any model load or network
    # access. Callers catch RuntimeError and degrade gracefully.
    try:
        from webpent.config.settings import get_settings
        settings = get_settings()
        if getattr(settings, "disable_rag", False):
            logger.info(
                "DISABLE_RAG=true — RAG subsystem explicitly disabled. "
                "No embeddings model loaded; RAG retrieval will return empty."
            )
            raise RuntimeError(
                "RAG disabled via DISABLE_RAG=true — no embeddings loaded."
            )
        offline_mode = bool(getattr(settings, "embeddings_offline", False))
    except RuntimeError:
        raise
    except Exception:
        # Settings load failure — proceed with online mode (legacy
        # behaviour) rather than blocking the scan.
        offline_mode = False

    try:
        from langchain_community.embeddings import HuggingFaceEmbeddings
    except ImportError as exc:
        raise RuntimeError(
            "langchain_community is not installed. Install it with "
            "'pip install langchain-community sentence-transformers'."
        ) from exc

    try:
        logger.info(
            "Loading SentenceTransformers embedding model %r (first run "
            "may download ~80MB%s)...",
            _DEFAULT_MODEL_NAME,
            "; offline mode — cache only" if offline_mode else "",
        )
        # V10 P0-2: when offline_mode is True, pass local_files_only=True
        # so HuggingFaceEmbeddings does NOT hit huggingface.co. If the
        # model is not cached, this raises immediately instead of
        # stalling on a multi-minute network download.
        kwargs: dict = {"model_name": _DEFAULT_MODEL_NAME}
        if offline_mode:
            kwargs["model_kwargs"] = {"local_files_only": True}
        embeddings = HuggingFaceEmbeddings(**kwargs)
        logger.info("Embedding model loaded successfully.")
        return embeddings
    except Exception as exc:
        if offline_mode:
            raise RuntimeError(
                f"Failed to load embedding model {_DEFAULT_MODEL_NAME!r} in "
                f"offline mode (EMBEDDINGS_OFFLINE=true). The model is NOT "
                f"in the local HuggingFace cache. Either (1) pre-populate "
                f"the cache by running once without EMBEDDINGS_OFFLINE, or "
                f"(2) set DISABLE_RAG=true to skip RAG entirely. "
                f"Original error: {exc}"
            ) from exc
        raise RuntimeError(
            f"Failed to load embedding model {_DEFAULT_MODEL_NAME!r}. "
            f"Ensure 'sentence-transformers' is installed and the model "
            f"can be downloaded. Original error: {exc}"
        ) from exc
