# worker.py
"""Root-level script to expose the Celery application for the worker process.

Usage:
    celery -A worker.celery_app worker --loglevel=info

This module re-exports ``celery_app`` from
``webpent.workers.pentest_worker`` so the Celery CLI can discover it
without a long dotted path. The actual Celery configuration and task
definition live in :mod:`webpent.workers.pentest_worker`.
"""

from __future__ import annotations

from webpent.workers.pentest_worker import celery_app

__all__ = ["celery_app"]
