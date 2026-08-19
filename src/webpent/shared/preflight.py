"""webpent.shared.preflight

V10 P0-1 (RCA follow-up): startup capability preflight.

Audits across multiple review rounds flagged that worker boot silently
normalised "Alembic missing" + "WebSocket SSRF unmitigated" + "embeddings
network hang" + "insecure CELERY_PAYLOAD_KEY" as quiet success without
operator-visible capability status. This module provides a single
:func:`run_preflight` function that the API and worker can call at
startup to emit an INFO-level capability report. It does NOT block
startup (the framework degrades gracefully by design) — it makes the
degradation VISIBLE so the operator knows which capabilities are
available and which are in degraded mode.

The report covers:
  1. Alembic — is the migration tooling importable + alembic.ini present?
  2. Playwright WebSocket SSRF guard — does the installed Playwright
     version support ``route_web_socket()`` (>=1.48)? If not, the WS
     SSRF bypass is UNMITIGATED and the operator must know.
  3. Embeddings — is the RAG embedding model loadable offline, or is
     EMBEDDINGS_OFFLINE/DISABLE_RAG set (see webpent.memory.embeddings)?
  4. CELERY_PAYLOAD_KEY — is the broker credential-encryption key a
     strong custom value, or the insecure dev default?

Usage (API/worker startup):
    from webpent.shared.preflight import run_preflight
    run_preflight()
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _check_alembic() -> dict[str, object]:
    """Check whether Alembic migration tooling is available."""
    try:
        from pathlib import Path

        import alembic

        # alembic.ini lives at the project root (next to pyproject.toml).
        # The path is relative to this file: ../../../../alembic.ini
        # (src/webpent/shared/preflight.py -> src/webpent/shared ->
        #  src/webpent -> src -> project root).
        ini_path = Path(__file__).resolve().parents[4] / "alembic.ini"
        ini_present = ini_path.exists()
        return {
            "available": True,
            "version": getattr(alembic, "__version__", "unknown"),
            "ini_present": ini_present,
            "status": "ok" if ini_present else "degraded (alembic.ini missing)",
        }
    except ImportError as exc:
        return {
            "available": False,
            "status": f"degraded (alembic not importable: {exc})",
        }


def _check_playwright_ws_guard() -> dict[str, object]:
    """Check whether Playwright supports route_web_socket() (>=1.48).

    The pyproject.toml pins playwright>=1.40.0,<1.41, which does NOT
    support route_web_socket() (added in 1.48). The HTTP SSRF guard
    works on all versions, but the WebSocket SSRF guard is unavailable
    on <1.48 — a malicious page could open a WebSocket to an internal
    host and bypass the HTTP guard entirely.

    This check does NOT block startup — it makes the residual risk
    visible so the operator knows the WS bypass is unmitigated.
    """
    try:
        import playwright

        version = getattr(playwright, "__version__", "unknown")
        # route_web_socket was added in Playwright 1.48. Parse the
        # major.minor to determine availability.
        try:
            parts = version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            supports_ws_guard = (major > 1) or (major == 1 and minor >= 48)
        except (ValueError, IndexError):
            supports_ws_guard = False
        return {
            "version": version,
            "ws_guard_available": supports_ws_guard,
            "status": (
                "ok (WebSocket SSRF guard active)"
                if supports_ws_guard
                else "DEGRADED — WebSocket SSRF bypass UNMITIGATED "
                "(upgrade Playwright to >=1.48 to enable)"
            ),
        }
    except ImportError:
        return {
            "version": None,
            "ws_guard_available": False,
            "status": "degraded (playwright not installed — browser exploitation unavailable)",
        }


def _check_embeddings() -> dict[str, object]:
    """Check whether the RAG embedding model is loadable offline."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        # V10 P0-2: EMBEDDINGS_OFFLINE / DISABLE_RAG switches.
        if getattr(settings, "disable_rag", False):
            return {
                "mode": "disabled (DISABLE_RAG=true)",
                "status": "ok — RAG explicitly disabled, no HF network access",
            }
        if getattr(settings, "embeddings_offline", False):
            return {
                "mode": "offline (EMBEDDINGS_OFFLINE=true)",
                "status": "ok — embeddings will use cache only; first-run download skipped",
            }
        # Check whether the model is already cached locally.
        from pathlib import Path

        cache_dir = Path.home() / ".cache" / "huggingface"
        cache_present = cache_dir.exists() and any(cache_dir.iterdir())
        return {
            "mode": "online (first-run may download ~80MB from huggingface.co)",
            "cache_present": cache_present,
            "status": (
                "ok — model cached locally, no network needed"
                if cache_present
                else "degraded — model NOT cached; first RAG query will "
                "hit huggingface.co (set EMBEDDINGS_OFFLINE=true to "
                "skip, or pre-populate the cache)"
            ),
        }
    except Exception as exc:
        return {
            "mode": "unknown",
            "status": f"degraded (preflight check failed: {exc})",
        }


def _check_celery_payload_key() -> dict[str, object]:
    """Check whether the Celery broker credential-encryption key is strong."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        key = settings.celery_payload_key
        is_default = key in getattr(settings, "_INSECURE_CELERY_PAYLOAD_DEFAULTS", set())
        is_short = len(key) < 32
        if settings.auth_enabled and is_default:
            return {
                "posture": "INSECURE (prod with default key — Settings() should have raised)",
                "status": "FAIL — auth_enabled=True with default CELERY_PAYLOAD_KEY",
            }
        if is_default:
            return {
                "posture": "dev default (acceptable for local lab)",
                "status": "ok for dev — set CELERY_PAYLOAD_KEY for any non-local deployment",
            }
        if is_short:
            return {
                "posture": f"too short ({len(key)} chars, need >=32)",
                "status": "FAIL — CELERY_PAYLOAD_KEY too short",
            }
        return {
            "posture": "strong custom key",
            "status": "ok — broker credentials encrypted with strong key",
        }
    except Exception as exc:
        return {
            "posture": "unknown",
            "status": f"degraded (preflight check failed: {exc})",
        }


def _check_llm_providers() -> dict[str, object]:
    """Report configured LLM providers and usable fallback chains without API calls."""
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.llm import (
            _TASK_PREFERENCE_ORDER,
            TaskType,
            _api_key_for_provider,
            get_dead_providers,
            is_llm_enabled,
        )

        settings = get_settings()
        configured: dict[str, bool] = {}
        for chain in _TASK_PREFERENCE_ORDER.values():
            for provider, _model in chain:
                configured[provider] = bool(_api_key_for_provider(provider, settings))
        available = sorted(name for name, ready in configured.items() if ready)
        chains: dict[str, list[str]] = {}
        for task in TaskType:
            chains[task.value] = [
                f"{provider}:{model}"
                for provider, model in _TASK_PREFERENCE_ORDER[task]
                if configured.get(provider, False)
            ]
        enabled = is_llm_enabled(settings)
        dead = sorted(get_dead_providers())
        return {
            "enabled": enabled,
            "configured_providers": available,
            "configured_count": len(available),
            "dead_providers": dead,
            "fallback_chains": chains,
            "status": (
                "disabled — deterministic fallbacks active"
                if not enabled
                else "ok — at least one configured provider"
                if available
                else "degraded — no configured provider; deterministic fallbacks only"
            ),
        }
    except Exception as exc:
        return {
            "enabled": False,
            "configured_providers": [],
            "configured_count": 0,
            "dead_providers": [],
            "fallback_chains": {},
            "status": f"degraded (LLM diagnostics failed: {type(exc).__name__})",
        }


def _truthy_env(name: str) -> bool:
    """Return whether an environment switch is explicitly enabled."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _redis_posture(url: str, *, name: str) -> dict[str, object]:
    """Describe Redis transport and whether the URL has an ACL identity."""
    if not url:
        return {"configured": False, "status": "not configured"}
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    secure = scheme == "rediss"
    has_password = bool(parsed.password)
    has_username = bool(parsed.username)
    return {
        "configured": True,
        "scheme": scheme,
        "tls": secure,
        "acl_identity_present": has_username or has_password,
        "status": (
            "ok — TLS transport enabled"
            if secure
            else f"DEGRADED — {name} uses plaintext Redis transport"
        ),
    }


def _check_redis_security() -> dict[str, object]:
    """Check broker and rate-limit Redis URLs without making a network call."""
    broker_url = os.getenv("WEBPENT_REDIS_URL", "redis://localhost:6379/0")
    rate_url = os.getenv("WEBPENT_RATE_LIMIT_REDIS_URL", "")
    broker = _redis_posture(broker_url, name="Celery broker")
    rate_limit = _redis_posture(rate_url, name="rate limiter")
    insecure = any(item.get("configured") and not item.get("tls") for item in (broker, rate_limit))
    return {
        "status": (
            "DEGRADED — plaintext Redis transport detected"
            if insecure
            else "ok — Redis transport posture is acceptable"
        ),
        "broker": broker,
        "rate_limit": rate_limit,
    }


def _enforce_redis_security(report: dict[str, dict[str, object]]) -> None:
    """Require TLS for Redis whenever authentication is enabled."""
    try:
        from webpent.config.settings import get_settings

        auth_enabled = get_settings().auth_enabled
    except Exception as exc:
        raise SystemExit("Preflight blocked startup: Redis security posture is unknown") from exc
    if not auth_enabled or _truthy_env("WEBPENT_ALLOW_PLAINTEXT_REDIS"):
        return
    broker = report["redis_security"]["broker"]
    rate_limit = report["redis_security"]["rate_limit"]
    insecure = any(item.get("configured") and not item.get("tls") for item in (broker, rate_limit))
    if insecure:
        raise SystemExit(
            "Preflight blocked startup: AUTH_ENABLED=true requires rediss:// for Redis "
            "broker and rate limiter (or an explicit lab-only override)"
        )


def _enforce_api_security_posture(
    *,
    host: str | None,
    report: dict[str, dict[str, object]],
) -> None:
    """Fail closed for the known unsafe public-bind configuration.

    ``run_preflight()`` is also used by unit tests and local library imports,
    so the bind host is deliberately an explicit input. API/worker startup
    passes ``WEBPENT_API_HOST`` when the process bind address is known. This
    avoids guessing that an arbitrary local test process is public while still
    enforcing the dangerous production combination at the actual startup
    boundary.
    """
    normalized_host = (host or "").strip().lower()
    # Evaluate the posture from the same Settings object as the middleware.
    # Auth-off is a loopback-only development mode; wildcard CORS and disabled
    # rate limiting are additional indicators, not prerequisites for blocking
    # a public bind.
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        public_bind = normalized_host in {
            "0.0.0.0",
            "::",
            "0:0:0:0:0:0:0:0",
        }
        insecure_combo = public_bind and settings.auth_enabled is False
    except Exception as exc:
        # Settings construction already has its own hard stops for secret
        # posture. A failed read must not turn this gate into an accidental
        # bypass when the host is public.
        if normalized_host == "0.0.0.0":
            raise SystemExit(
                "Preflight blocked startup: security settings could not be evaluated "
                "for a 0.0.0.0 bind"
            ) from exc
        return

    if not insecure_combo:
        return

    if _truthy_env("I_UNDERSTAND_THIS_IS_INSECURE"):
        report["api_security_posture"] = {
            "host": normalized_host,
            "status": "OVERRIDDEN — insecure public bind explicitly acknowledged",
        }
        logger.critical(
            "[preflight] INSECURE OVERRIDE: public bind with auth disabled; "
            "this is permitted only for an explicitly acknowledged isolated lab",
        )
        return

    report["api_security_posture"] = {
        "host": normalized_host,
        "status": "FAIL — unsafe public bind configuration",
    }
    logger.critical(
        "[preflight] BLOCKED: refusing public bind with auth disabled; "
        "enable authentication or use a loopback bind. "
        "I_UNDERSTAND_THIS_IS_INSECURE=true is a lab-only override",
    )
    raise SystemExit(
        "Preflight blocked startup: unsafe 0.0.0.0/public bind with auth "
        "disabled; enable auth or use a loopback bind"
    )


def run_preflight(host: str | None = None) -> dict[str, dict[str, object]]:
    """Emit the capability report and enforce public-bind security posture.

    ``host`` is explicit so importing the module or running local unit tests
    does not guess a network bind address. Production API/worker entrypoints
    pass ``WEBPENT_API_HOST``. When that value is ``0.0.0.0``, the unsafe
    quartet (auth disabled + wildcard CORS + rate limiting disabled) raises
    ``SystemExit`` unless the operator explicitly sets
    ``I_UNDERSTAND_THIS_IS_INSECURE=true``.
    """
    report = {
        "alembic": _check_alembic(),
        "playwright_ws_guard": _check_playwright_ws_guard(),
        "embeddings": _check_embeddings(),
        "celery_payload_key": _check_celery_payload_key(),
        "redis_security": _check_redis_security(),
        "llm": _check_llm_providers(),
    }
    try:
        from webpent.shared.capability_manifest import build_capability_manifest

        manifest = build_capability_manifest()
        manifest["status"] = "degraded" if manifest.get("blockers") else "ok"
        report["capability_manifest"] = manifest
    except Exception as exc:
        # Capability reporting must never become an accidental authorization
        # bypass. A malformed or unavailable manifest is an explicit blocker.
        report["capability_manifest"] = {
            "status": "degraded",
            "profile": "unknown",
            "capabilities": {},
            "blockers": [{"capability": "manifest", "reason": type(exc).__name__}],
            "fail_closed": True,
        }
    _enforce_redis_security(report)
    _enforce_api_security_posture(host=host, report=report)
    # Emit one INFO line per capability so the operator sees the full
    # posture at boot. Each line is prefixed with "[preflight]" for
    # easy grep.
    for name, info in report.items():
        status = info.get("status", "unknown")
        logger.info("[preflight] %s: %s", name, status)
    return report
