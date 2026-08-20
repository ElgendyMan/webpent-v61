"""Deterministic runtime capability reporting for Smart Autonomous mode.

The manifest is deliberately side-effect free. It reports what the current
process can safely do; it does not install tools, open network connections, or
change scope. Callers must treat ``blocked`` capabilities as unavailable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

from webpent.config.settings import ScanMode, Settings, get_settings


def _tool_status(path: str) -> dict[str, Any]:
    """Return a redacted availability record for one local executable."""
    configured = str(path or "").strip()
    if not configured:
        return {"available": False, "status": "not_configured"}
    resolved = shutil.which(configured)
    return {
        "available": resolved is not None,
        "status": "available" if resolved else "infrastructure_failure",
        "configured": configured[:160],
    }


def resolve_browser_executable() -> str | None:
    """Resolve a validated local Chromium executable without downloading anything."""
    configured = os.getenv("WEBPENT_CHROMIUM_PATH", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None
    for name in ("chromium", "chromium-browser", "google-chrome"):
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


@lru_cache(maxsize=4)
def _browser_metadata(path: str | None) -> dict[str, Any]:
    """Return non-secret version/hash metadata for a validated executable."""
    if not path:
        return {}
    metadata: dict[str, Any] = {"executable_path": path}
    try:
        metadata["sha256"] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        metadata["sha256"] = None
    try:
        completed = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        version = (completed.stdout or completed.stderr).strip()
        metadata["version"] = version[:160] if version else "unknown"
    except (OSError, subprocess.SubprocessError):
        metadata["version"] = "unknown"
    return metadata


def _playwright_status() -> dict[str, Any]:
    """Check the Python package and a validated local Chromium executable separately."""
    package_available = importlib.util.find_spec("playwright") is not None
    browser_path = resolve_browser_executable()
    available = package_available and browser_path is not None
    return {
        "available": available,
        "status": "available" if available else "infrastructure_failure",
        "package_available": package_available,
        "browser_executable_available": browser_path is not None,
        **_browser_metadata(browser_path),
    }


class CapabilityRegistry:
    """Lazy, redaction-safe registry for runtime capabilities and fallbacks."""

    _FALLBACKS = {
        "browser": "human_review_only",
        "httpx": "native_http",
        "katana": "native_crawler",
        "nuclei": "native_validator",
        "ffuf": "native_parameter_probe",
        "oob": "inconclusive_without_controlled_callback",
        "autopentestx_observation": "native_recon_or_human_review",
    }

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self._manifest: dict[str, Any] | None = None

    def ensure_discovered(self) -> dict[str, Any]:
        """Build the manifest once; discovery never installs tools or opens network I/O."""
        if self._manifest is None:
            self._manifest = _build_capability_manifest(self.settings)
        return self._manifest

    def get(self, capability: str) -> dict[str, Any]:
        """Return a safe capability record; malformed names are unavailable."""
        name = str(capability or "").strip()[:80]
        record = (self.ensure_discovered().get("capabilities") or {}).get(name)
        return dict(record) if isinstance(record, dict) else {
            "available": False,
            "status": "unknown_capability",
        }

    def available(self, capability: str) -> bool:
        return self.get(capability).get("available") is True

    def blocker(self, capability: str, *, reason: str = "") -> dict[str, Any]:
        """Return a typed fail-closed blocker with a deterministic fallback."""
        record = self.get(capability)
        return {
            "kind": "capability_blocker",
            "capability": str(capability or "")[:80],
            "status": str(record.get("status") or "unavailable"),
            "reason": str(reason or record.get("status") or "unavailable")[:200],
            "fallback": self._FALLBACKS.get(str(capability or ""), "safe_stop"),
            "fail_closed": True,
        }

    def diagnostics(self) -> dict[str, Any]:
        manifest = self.ensure_discovered()
        return {
            "profile": manifest.get("profile", "unknown"),
            "capabilities": sorted((manifest.get("capabilities") or {}).keys()),
            "blocker_count": len(manifest.get("blockers") or []),
            "fail_closed": manifest.get("fail_closed") is True,
        }


def _build_capability_manifest(settings: Settings | None = None) -> dict[str, Any]:
    """Build a non-secret capability manifest for the current scan profile."""
    settings = settings or get_settings()
    mode = getattr(settings.scan_mode, "value", settings.scan_mode)
    environment_profile = getattr(
        settings.environment_profile, "value", settings.environment_profile
    )
    capabilities: dict[str, dict[str, Any]] = {
        "http_read": {"available": True, "status": "available"},
        "autopentestx_observation": {
            "available": True,
            "status": "adapter_only",
            "execution_available": False,
            "network_io": False,
            "subprocess_io": False,
            "authority": "webpent_validator",
            "source_commit": "c324bc5b8aa68b549652c403fd674b142617f211",
            "timeout_seconds": 0,
            "retry_budget": 0,
            "concurrency_limit": 1,
            "max_input_bytes": 512 * 1024,
            "max_records": 256,
            "partial_output_supported": True,
            "cleanup": "not_applicable_import_only",
            "fail_closed": True,
        },
        "browser": _playwright_status(),
        "oob": {
            "available": bool(settings.oob_callback_base_url and settings.oob_callback_secret),
            "status": (
                "available"
                if settings.oob_callback_base_url and settings.oob_callback_secret
                else "blocked_by_precondition"
            ),
        },
        "llm": {
            "available": bool(settings.llm_enabled),
            "status": "available" if settings.llm_enabled else "disabled",
        },
        "httpx": _tool_status(settings.httpx_path),
        "katana": _tool_status(settings.katana_path),
        "nuclei": _tool_status(settings.nuclei_path),
        "ffuf": _tool_status(settings.ffuf_path) if settings.ffuf_enabled else {
            "available": False,
            "status": "disabled",
        },
    }
    if mode == ScanMode.AUTHORIZED_ACTIVE.value:
        capabilities["active_workflow"] = {
            "available": True,
            "status": "available",
            "policy": "authorized-active-only",
        }
    else:
        capabilities["active_workflow"] = {
            "available": False,
            "status": "disabled_by_profile",
            "policy": "read-only",
        }

    blockers: list[dict[str, str]] = []
    for name, record in capabilities.items():
        if not record.get("available") and name in {
            "browser",
            "oob",
            "httpx",
            "katana",
            "nuclei",
            "active_workflow",
        }:
            blockers.append(
                {"capability": name, "reason": str(record.get("status", "unavailable"))}
            )

    return {
        "profile": str(mode),
        "environment_profile": str(environment_profile),
        "capabilities": capabilities,
        "blockers": blockers,
        "fail_closed": True,
    }


def build_capability_manifest(settings: Settings | None = None) -> dict[str, Any]:
    """Backward-compatible public builder backed by the lazy registry."""
    return CapabilityRegistry(settings).ensure_discovered()


def capability_available(manifest: dict[str, Any], capability: str) -> bool:
    """Safely query a manifest without treating malformed data as available."""
    record = (manifest.get("capabilities") or {}).get(capability)
    return isinstance(record, dict) and record.get("available") is True
