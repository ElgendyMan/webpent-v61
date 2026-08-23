#!/usr/bin/env python3
"""Read-only WebPent runtime diagnostics.

The harness checks local prerequisites and configuration without changing files,
starting services, sending LLM prompts, or probing targets unless the operator
explicitly enables ``--network-checks``/``--probe-url``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE_ROOT = Path.home() / ".webpent" / "workspaces"
LLM_PROVIDERS = (
    "groq",
    "openai",
    "local",
    "openrouter",
    "github",
    "cerebras",
    "zai",
    "mistral",
    "gemini",
    "cohere",
    "cloudflare",
)
REQUIRED_IMPORTS = {
    "fastapi": "FastAPI/API",
    "langgraph": "graph execution",
    "pydantic": "state validation",
    "playwright": "browser validation",
    "redis": "Redis transport",
    "celery": "worker runtime",
    "chromadb": "RAG/vector store",
}
REQUIRED_BINARIES = ("git", "curl")
OPTIONAL_BINARIES = (
    "docker",
    "redis-server",
    "celery",
    "nuclei",
    "katana",
    "ffuf",
    "dalfox",
    "sqlmap",
)
TOOLCHAIN_CONTRACT = {
    "nuclei": {
        "binary": "nuclei",
        "version_args": ["-version"],
        "expected_version": "v3.9.0",
    },
    "subfinder": {
        "binary": "subfinder",
        "version_args": ["-version"],
        "expected_version": "v2.9.0",
    },
    "httpx": {
        "binary": "httpx-pd",
        "version_args": ["-version"],
        "expected_version": "v1.9.0",
    },
    "katana": {
        "binary": "katana",
        "version_args": ["-version"],
        "expected_version": "v1.7.0",
    },
    "dalfox": {
        "binary": "dalfox",
        "version_args": ["version"],
        "expected_version": "v2.12.0",
    },
    "ffuf": {
        "binary": "ffuf",
        "version_args": ["-V"],
        "expected_version": "2.1.0",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "version_args": ["--version"],
        "expected_version": "1.8",
    },
}
TEMPLATE_MANIFEST_SCHEMA = "nuclei-template-manifest-v1"


@dataclass(frozen=True)
class Finding:
    check_id: str
    component: str
    status: str
    severity: str
    observed: str
    expected: str
    likely_cause: str
    remediation: str
    retryability: str
    evidence: dict[str, Any]
    network_access: bool


def finding(
    check_id: str,
    component: str,
    status: str,
    severity: str,
    observed: str,
    expected: str,
    likely_cause: str,
    remediation: str,
    retryability: str = "not_applicable",
    evidence: dict[str, Any] | None = None,
    network_access: bool = False,
) -> Finding:
    return Finding(
        check_id=check_id,
        component=component,
        status=status,
        severity=severity,
        observed=observed,
        expected=expected,
        likely_cause=likely_cause,
        remediation=remediation,
        retryability=retryability,
        evidence=evidence or {},
        network_access=network_access,
    )


def _run_command(args: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    stdout = " ".join(completed.stdout.split())[:500]
    stderr = " ".join(completed.stderr.split())[:500]
    return completed.returncode, stdout, stderr


def _toolchain_command(name: str) -> tuple[int, str, str]:
    contract = TOOLCHAIN_CONTRACT[name]
    binary = contract["binary"]
    path = shutil.which(binary)
    if not path:
        return 127, "", "command not found"
    return _run_command([path, *contract["version_args"]], timeout=5.0)


def _template_manifest_path() -> Path:
    configured = os.getenv("WEBPENT_NUCLEI_TEMPLATE_MANIFEST", "").strip()
    if configured:
        return Path(configured).expanduser()
    configured_root = os.getenv("WEBPENT_NUCLEI_TEMPLATE_DIR", "").strip()
    if configured_root:
        return Path(configured_root).expanduser() / "manifest.json"
    return PROJECT_ROOT / ".nuclei-template-manifest.json"


def _read_nuclei_template_manifest() -> dict[str, Any] | None:
    path = _template_manifest_path()
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict):
        return None
    digest = manifest.get("digest")
    file_count = manifest.get("file_count")
    if (
        manifest.get("schema_version") != TEMPLATE_MANIFEST_SCHEMA
        or not isinstance(manifest.get("version"), str)
        or not manifest["version"].strip()
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest.lower())
        or not isinstance(file_count, int)
        or file_count < 1
    ):
        return None
    return {
        "schema_version": manifest["schema_version"],
        "version": manifest["version"].strip(),
        "digest": digest.lower(),
        "file_count": file_count,
        "total_bytes": manifest.get("total_bytes", 0),
    }


def check_toolchain() -> list[Finding]:
    results: list[Finding] = []
    for name, contract in TOOLCHAIN_CONTRACT.items():
        code, stdout, stderr = _toolchain_command(name)
        output = stdout or stderr or f"exit={code}"
        expected = contract["expected_version"]
        version_match = code == 0 and expected in output
        status = "PASS" if version_match else "WARN"
        results.append(
            finding(
                f"toolchain.{name}",
                f"{name} security tool",
                status,
                "info" if version_match else "warning",
                output[:180],
                f"{contract['binary']} reports pinned version containing {expected}",
                (
                    "binary is missing, version output is unavailable, or the installed "
                    "version differs from the release contract"
                ),
                (
                    f"install the pinned {contract['binary']} binary in the approved image "
                    "and rerun diagnostics"
                ),
                retryability="after_install_or_image_rebuild",
                evidence={
                    "binary": contract["binary"],
                    "expected_version": expected,
                    "exit_code": code,
                    "version_output_redacted": True,
                },
            )
        )

    manifest = _read_nuclei_template_manifest()
    expected_tool_version = TOOLCHAIN_CONTRACT["nuclei"]["expected_version"]
    manifest_valid = bool(
        manifest and expected_tool_version in str(manifest.get("version", ""))
    )
    results.append(
        finding(
            "toolchain.templates",
            "Nuclei template set",
            "PASS" if manifest_valid else "BLOCKED",
            "info" if manifest_valid else "error",
            (
                f"version={manifest.get('version')}, files={manifest.get('file_count', 0)}"
                if manifest
                else "template manifest missing or invalid"
            ),
            (
                "a valid nuclei-template-manifest-v1 with a non-empty file set and "
                f"provenance for {expected_tool_version}"
            ),
            (
                "template content is absent, malformed, empty, or not tied to the "
                "pinned Nuclei version"
            ),
            (
                "rebuild the approved image with Nuclei template update enabled; never "
                "run a coverage claim with an untracked template set"
            ),
            retryability="after_image_rebuild",
            evidence={
                "manifest_present": manifest is not None,
                "schema_version": manifest.get("schema_version") if manifest else None,
                "version": manifest.get("version") if manifest else None,
                "digest": manifest.get("digest") if manifest else None,
                "file_count": manifest.get("file_count") if manifest else 0,
                "manifest_path_redacted": True,
            },
        )
    )
    return results


def check_project() -> list[Finding]:
    readable = os.access(PROJECT_ROOT, os.R_OK)
    writable = os.access(PROJECT_ROOT, os.W_OK)
    return [
        finding(
            "project.permissions",
            "filesystem",
            "PASS" if readable and writable else "BLOCKED",
            "info" if readable and writable else "error",
            f"readable={readable}, writable={writable}",
            "project root readable and writable for local development",
            "filesystem permissions or ownership are restrictive",
            "fix ownership/permissions for the invoking user; do not run scans as root by default",
            evidence={"path": str(PROJECT_ROOT)},
        )
    ]


def check_python() -> list[Finding]:
    version = platform.python_version()
    major_minor = sys.version_info[:2]
    supported = major_minor >= (3, 11)
    return [
        finding(
            "python.version",
            "python",
            "PASS" if supported else "BLOCKED",
            "info" if supported else "error",
            version,
            "Python >= 3.11",
            "interpreter is older than the project runtime contract",
            "use the pinned project Python runtime and recreate the environment",
            evidence={"implementation": platform.python_implementation()},
        )
    ]


def check_imports() -> list[Finding]:
    results: list[Finding] = []
    for module, purpose in REQUIRED_IMPORTS.items():
        present = importlib.util.find_spec(module) is not None
        results.append(
            finding(
                f"dependency.import.{module}",
                purpose,
                "PASS" if present else "BLOCKED",
                "info" if present else "error",
                "import spec found" if present else "import spec missing",
                f"{module} importable",
                "dependency is absent or the active environment is not the project environment",
                (
                    "install the dependency from the project lock/requirements "
                    "using the supported environment"
                ),
                retryability="after_dependency_fix",
                evidence={"module": module},
            )
        )
    return results


def check_pip() -> list[Finding]:
    code, stdout, stderr = _run_command([sys.executable, "-m", "pip", "check"])
    passed = code == 0
    return [
        finding(
            "dependency.pip_check",
            "python dependencies",
            "PASS" if passed else "BLOCKED",
            "info" if passed else "error",
            stdout or stderr or f"exit={code}",
            "pip check exits zero",
            "dependency metadata is inconsistent or a package is missing",
            (
                "reinstall from uv.lock/pyproject.toml and rerun pip check; "
                "do not mutate production during a scan"
            ),
            retryability="after_dependency_fix",
            evidence={"exit_code": code},
        )
    ]


def check_binaries() -> list[Finding]:
    results: list[Finding] = []
    for name in REQUIRED_BINARIES:
        path = shutil.which(name)
        results.append(
            finding(
                f"binary.required.{name}",
                "system binaries",
                "PASS" if path else "BLOCKED",
                "info" if path else "error",
                path or "not found",
                f"{name} available on PATH",
                "required command-line dependency is unavailable",
                f"install {name} through the operating system package manager",
                retryability="after_install",
                evidence={"path": path},
            )
        )
    for name in OPTIONAL_BINARIES:
        path = shutil.which(name)
        results.append(
            finding(
                f"binary.optional.{name}",
                "external tools",
                "PASS" if path else "SKIPPED",
                "info" if path else "warning",
                path or "not found",
                f"{name} available when its adapter is enabled",
                "optional adapter binary is not installed or not on PATH",
                (
                    f"install {name} only if the corresponding policy-checked "
                    "adapter is intentionally enabled"
                ),
                retryability="after_install",
                evidence={"path": path, "optional": True},
            )
        )
    return results


def check_oob() -> list[Finding]:
    """Check OOB provider configuration without contacting any provider."""
    provider = os.getenv("WEBPENT_OOB_PROVIDER", "local").strip().lower() or "local"
    if provider == "local":
        return [
            finding(
                "oob.provider",
                "OOB callback provider",
                "PASS",
                "info",
                "local authenticated callback selected",
                "local callback/DB path remains the default offline-safe provider",
                "no external OOB provider is selected",
                "configure an explicit self-hosted provider only when its runtime is authorized",
                evidence={
                    "provider": "local",
                    "server_configured": False,
                    "binary_available": False,
                    "external_contacted": False,
                    "token_present": False,
                },
            )
        ]
    if provider != "interactsh":
        return [
            finding(
                "oob.provider",
                "OOB callback provider",
                "BLOCKED",
                "error",
                f"unsupported provider={provider}",
                "OOB_PROVIDER is local or explicit interactsh",
                "an unsupported provider name would bypass a known safety contract",
                "set WEBPENT_OOB_PROVIDER=local or interactsh; do not add implicit providers",
                retryability="after_configuration_fix",
                evidence={"provider": provider, "external_contacted": False},
            )
        ]

    binary = os.getenv("WEBPENT_INTERACTSH_BINARY", "interactsh-client").strip()
    server = os.getenv("WEBPENT_INTERACTSH_SERVER", "").strip()
    token_present = bool(os.getenv("WEBPENT_INTERACTSH_TOKEN", ""))
    binary_available = bool(binary and shutil.which(binary))
    server_configured = bool(server and urlparse(server).scheme in {"http", "https"})
    if not server_configured or not binary_available:
        return [
            finding(
                "oob.provider",
                "Interactsh OOB provider",
                "BLOCKED",
                "error",
                (
                    f"provider=interactsh, server_configured={server_configured}, "
                    f"binary_available={binary_available}"
                ),
                "explicit self-hosted server and interactsh-client binary are configured",
                "external OOB is enabled without all required local configuration",
                (
                    "set an operator-approved self-hosted INTERACTSH_SERVER and install "
                    "the reviewed binary"
                ),
                retryability="after_configuration_fix_or_install",
                evidence={
                    "provider": "interactsh",
                    "server_configured": server_configured,
                    "binary_available": binary_available,
                    "binary_name_redacted": bool(binary),
                    "external_contacted": False,
                    "token_present": token_present,
                },
            )
        ]
    return [
        finding(
            "oob.provider",
            "Interactsh OOB provider",
            "WARN",
            "warning",
            "explicit server and binary configured; no provider smoke test performed",
            "configuration is present before an operator-authorized self-hosted smoke test",
            (
                "configuration alone does not prove server reachability, payload correlation, "
                "or finding confirmation"
            ),
            (
                "run a bounded self-hosted smoke test with independent correlation and "
                "negative control; never promote from configuration alone"
            ),
            retryability="after_authorized_smoke_test",
            evidence={
                "provider": "interactsh",
                "server_configured": True,
                "binary_available": True,
                "binary_name_redacted": bool(binary),
                "external_contacted": False,
                "token_present": token_present,
            },
        )
    ]


def check_docker(run_config: bool) -> list[Finding]:
    results: list[Finding] = []
    docker = shutil.which("docker")
    compose = False
    if docker:
        code, out, err = _run_command(["docker", "compose", "version"])
        compose = code == 0
        results.append(
            finding(
                "docker.compose",
                "Docker Compose",
                "PASS" if compose else "BLOCKED",
                "info" if compose else "error",
                out or err or f"exit={code}",
                "docker compose is available",
                "Docker is absent or Compose plugin is unavailable",
                "install/enable Docker Compose before attempting the worker stack",
                retryability="after_install",
                evidence={"exit_code": code},
            )
        )
        if run_config and compose:
            code, out, err = _run_command(["docker", "compose", "config", "--quiet"], timeout=20)
            valid = code == 0
            results.append(
                finding(
                    "docker.compose_config",
                    "Docker Compose configuration",
                    "PASS" if valid else "BLOCKED",
                    "info" if valid else "error",
                    out or err or f"exit={code}",
                    "compose config validates without starting services",
                    (
                        "required production environment variables are missing "
                        "or compose syntax is invalid"
                    ),
                    (
                        "provide secrets through a protected .env/secret manager "
                        "and rerun; never hard-code them"
                    ),
                    retryability="after_configuration_fix",
                    evidence={"exit_code": code, "network_checked": False},
                )
            )
    else:
        results.append(
            finding(
                "docker.engine",
                "Docker",
                "BLOCKED",
                "error",
                "docker not found on PATH",
                "Docker available for the Docker/worker phase",
                "Docker is not installed in the active environment",
                (
                    "install Docker before the Docker qualification phase; "
                    "local Python checks remain valid"
                ),
                retryability="after_install",
            )
        )
    return results


def _safe_path_from_sqlite_url(value: str | None) -> Path | None:
    if not value:
        return PROJECT_ROOT / "webpent.db"
    if not value.startswith("sqlite"):
        return None
    raw = value.split("///", 1)[1] if "///" in value else value.split(":", 1)[-1]
    raw = raw.split("?", 1)[0]
    path = Path(raw)
    return path if path.is_absolute() else PROJECT_ROOT / path


def check_sqlite() -> list[Finding]:
    url = os.getenv("WEBPENT_DATABASE_URL") or os.getenv("DATABASE_URL")
    db_path = _safe_path_from_sqlite_url(url)
    if db_path is None:
        return [
            finding(
                "database.sqlite",
                "SQLite/Alembic",
                "SKIPPED",
                "info",
                "non-SQLite DATABASE_URL configured",
                "SQLite diagnostics are only applicable to sqlite URLs",
                "a different database backend is selected",
                "run the backend-specific database health check for the selected deployment",
                evidence={"database_url_present": bool(url), "value_redacted": True},
            )
        ]
    if not db_path.exists():
        return [
            finding(
                "database.sqlite",
                "SQLite/Alembic",
                "WARN",
                "warning",
                f"database file absent: {db_path}",
                "database exists before a resumed/runtime qualification",
                "database has not been initialized in this workspace",
                "initialize the database through the supported application migration/startup path",
                retryability="after_initialization",
                evidence={"path": str(db_path), "exists": False},
            )
        ]
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        connection.close()
    except Exception as exc:
        return [
            finding(
                "database.sqlite",
                "SQLite/Alembic",
                "BLOCKED",
                "error",
                f"read-only integrity check failed: {type(exc).__name__}",
                "read-only SQLite integrity check passes",
                "database is locked, corrupt, inaccessible, or not a valid SQLite file",
                (
                    "stop writers and restore/rebuild through the supported "
                    "migration and backup procedure"
                ),
                retryability="after_database_recovery",
                evidence={"path": str(db_path)},
            )
        ]
    good = integrity == "ok"
    return [
        finding(
            "database.sqlite",
            "SQLite/Alembic",
            "PASS" if good else "BLOCKED",
            "info" if good else "error",
            f"integrity={integrity}, tables={len(tables)}",
            "SQLite integrity_check returns ok",
            "database integrity check failed",
            "restore/rebuild the database through the supported migration and backup procedure",
            retryability="after_database_recovery",
            evidence={"path": str(db_path), "table_count": len(tables)},
        )
    ]


def check_rag() -> list[Finding]:
    disabled = os.getenv("DISABLE_RAG", "").strip().lower() in {"1", "true", "yes", "on"}
    if disabled:
        return [
            finding(
                "rag.mode",
                "RAG/vector store",
                "SKIPPED",
                "warning",
                "DISABLE_RAG=true",
                "RAG enabled when RAG coverage is being evaluated",
                "operator explicitly disabled RAG",
                "unset DISABLE_RAG and verify the model/vector store before claiming RAG coverage",
                evidence={"network_access": False},
            )
        ]
    memory = Path(os.getenv("WEBPENT_MEMORY_DIR", str(PROJECT_ROOT / "memory")))
    writable = memory.exists() and os.access(memory, os.W_OK)
    return [
        finding(
            "rag.storage",
            "RAG/vector store",
            "PASS" if writable else "WARN",
            "info" if writable else "warning",
            f"path={memory}, writable={writable}",
            "RAG storage path exists and is writable when RAG is enabled",
            "memory path is absent or not writable",
            (
                "create/configure the isolated target memory path through the "
                "supported workspace setup"
            ),
            retryability="after_workspace_fix",
            evidence={"path": str(memory)},
        )
    ]


def check_playwright() -> list[Finding]:
    module = importlib.util.find_spec("playwright") is not None
    cache = Path.home() / ".cache" / "ms-playwright"
    browsers = list(cache.glob("chromium-*")) if cache.exists() else []
    good = module and bool(browsers)
    return [
        finding(
            "browser.playwright",
            "Playwright/Chromium",
            "PASS" if good else "WARN",
            "info" if good else "warning",
            f"module={module}, chromium_installations={len(browsers)}",
            "Playwright importable and Chromium browser installed",
            "Python package or browser binary is missing",
            (
                "install the pinned Playwright browser in the same environment; "
                "do not download during a scan"
            ),
            retryability="after_install",
            evidence={"cache_path": str(cache), "browser_count": len(browsers)},
        )
    ]


def check_llm() -> list[Finding]:
    enabled = os.getenv(
        "WEBPENT_LLM_ENABLED", os.getenv("LLM_ENABLED", "true")
    ).strip().lower() not in {"0", "false", "no", "off"}
    configured = []
    for provider in LLM_PROVIDERS:
        names = [f"{provider.upper()}_API_KEY"]
        if provider == "local":
            names = ["LOCAL_LLM_ENABLED", "LOCAL_LLM_URL"]
        if provider == "cloudflare":
            names += ["CLOUDFLARE_ACCOUNT_ID"]
        if any(os.getenv(name) for name in names):
            configured.append(provider)
    if not enabled:
        status, severity, observed = "PASS", "info", "LLM disabled; deterministic mode selected"
    elif configured:
        status, severity, observed = (
            "PASS",
            "info",
            f"configured_provider_names={','.join(configured)}",
        )
    else:
        status, severity, observed = (
            "WARN",
            "warning",
            "LLM enabled but no provider key/configuration was detected",
        )
    return [
        finding(
            "llm.configuration",
            "LLM configuration",
            status,
            severity,
            observed,
            "LLM enabled with at least one configured provider, or explicit deterministic mode",
            "provider keys/base URLs are absent or LLM is intentionally disabled",
            (
                "configure one provider through protected environment settings, "
                "or explicitly disable LLM and use bounded fallbacks"
            ),
            retryability="after_configuration_fix",
            evidence={
                "provider_names_only": configured,
                "values_redacted": True,
                "network_access": False,
            },
        )
    ]


def check_workspace() -> list[Finding]:
    root = Path(os.getenv("WEBPENT_WORKSPACE_ROOT", str(DEFAULT_WORKSPACE_ROOT))).expanduser()
    parent = root.parent if not root.exists() else root
    writable = parent.exists() and os.access(parent, os.W_OK)
    return [
        finding(
            "workspace.isolation_root",
            "target workspace",
            "PASS" if writable else "BLOCKED",
            "info" if writable else "error",
            f"root={root}, parent_writable={writable}",
            "workspace parent is writable for isolated target state",
            "workspace parent is missing or not writable",
            "configure a writable per-user workspace root; do not share target state directories",
            retryability="after_workspace_fix",
            evidence={"root": str(root), "exists": root.exists()},
        )
    ]


def check_ports(ports: list[int], enabled: bool) -> list[Finding]:
    if not ports:
        return [
            finding(
                "ports.configuration",
                "ports",
                "SKIPPED",
                "info",
                "no ports requested",
                "operator-selected ports",
                "no port list was supplied",
                "pass --ports 8000,6379,8080 when checking local services",
            )
        ]
    if not enabled:
        return [
            finding(
                f"port.localhost.{port}",
                "local service port",
                "SKIPPED",
                "warning",
                "network checks disabled",
                "explicit local connectivity result",
                "the operator did not opt into socket checks",
                "rerun with --network-checks for local service connectivity",
                evidence={"host": "127.0.0.1", "port": port},
            )
            for port in ports
        ]
    results: list[Finding] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            code = sock.connect_ex(("127.0.0.1", port))
        finally:
            sock.close()
        open_port = code == 0
        results.append(
            finding(
                f"port.localhost.{port}",
                "local service port",
                "PASS" if open_port else "WARN",
                "info" if open_port else "warning",
                "TCP connect succeeded" if open_port else f"TCP connect failed, errno={code}",
                "service is reachable only when explicitly expected",
                "service is stopped, bound elsewhere, or blocked",
                (
                    "start the intended local service and verify its bind address; "
                    "do not expose it publicly for this check"
                ),
                retryability="after_service_start",
                evidence={"host": "127.0.0.1", "port": port},
                network_access=True,
            )
        )
    return results


def check_redis(url: str | None, enabled: bool) -> list[Finding]:
    if not url:
        return [
            finding(
                "redis.configuration",
                "Redis",
                "SKIPPED",
                "info",
                "REDIS_URL not configured",
                "Redis URL when workers/API are enabled",
                "Redis is not configured in this process",
                (
                    "configure REDIS_URL through protected environment settings "
                    "before worker qualification"
                ),
                evidence={"value_redacted": True},
            )
        ]
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (6380 if parsed.scheme == "rediss" else 6379)
    if not enabled:
        return [
            finding(
                "redis.connectivity",
                "Redis",
                "SKIPPED",
                "warning",
                f"configured scheme={parsed.scheme}, host_present={bool(host)}, port={port}",
                "explicit connectivity result",
                "network checks disabled",
                (
                    "rerun with --network-checks to test a local/approved Redis "
                    "endpoint; value is never printed"
                ),
                evidence={"url_redacted": True},
            )
        ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        code = sock.connect_ex((host, port)) if host else 1
    finally:
        sock.close()
    reachable = code == 0
    return [
        finding(
            "redis.connectivity",
            "Redis",
            "PASS" if reachable else "BLOCKED",
            "info" if reachable else "error",
            f"scheme={parsed.scheme}, host_present={bool(host)}, port={port}, connect_errno={code}",
            "Redis TCP endpoint reachable when worker qualification is requested",
            "Redis is stopped, misaddressed, or blocked",
            "start/fix the approved Redis service and rerun; do not bypass TLS/auth requirements",
            retryability="after_service_fix",
            evidence={"url_redacted": True, "host_present": bool(host), "port": port},
            network_access=True,
        )
    ]


def build_runtime_qualification(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify the execution context without treating diagnostics as qualification.

    ``WEBPENT_RUNTIME_CONTEXT`` is an operator-supplied label, not an attestation.
    Runtime checks can identify blockers, but they cannot prove a deployable image,
    target-backed causal findings, negative controls, or replayable ProofBundles.
    """
    context = os.getenv("WEBPENT_RUNTIME_CONTEXT", "developer_sandbox").strip().lower()
    valid_contexts = {"developer_sandbox", "approved_container"}
    blocked_ids = [
        item["check_id"]
        for item in findings
        if item.get("status") == "BLOCKED"
    ]
    runtime_prefixes = (
        "dependency.",
        "binary.",
        "docker.",
        "toolchain.",
        "browser.",
        "workspace.",
    )
    runtime_blockers = [
        check_id for check_id in blocked_ids if check_id.startswith(runtime_prefixes)
    ]

    if context not in valid_contexts:
        classification = "unknown_runtime_context"
        evidence_basis = "unrecognized_operator_label"
    elif context == "developer_sandbox":
        classification = (
            "developer_sandbox_missing_dependencies"
            if runtime_blockers
            else "developer_sandbox_checks_only"
        )
        evidence_basis = "host_runtime_checks_only"
    elif runtime_blockers:
        classification = "approved_container_runtime_blocked"
        evidence_basis = "container_runtime_checks_only"
    else:
        classification = "approved_container_image_not_yet_qualified"
        evidence_basis = "container_runtime_checks_only"

    return {
        "context": context or "developer_sandbox",
        "classification": classification,
        "qualified": False,
        "evidence_basis": evidence_basis,
        "runtime_blockers": runtime_blockers,
        "qualification_note": (
            "runtime diagnostics are necessary preflight evidence only; independent "
            "authorized target-backed runs, negative controls, sealed ProofBundles, "
            "and successful replay are still required"
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    lines = ["WEBPENT DIAGNOSTICS", "=" * 96]
    lines.append(f"timestamp={report['timestamp']}  project={report['project_root']}")
    lines.append(f"summary={report['summary']}")
    runtime = report.get("runtime_qualification", {})
    if runtime:
        lines.append(
            "runtime_qualification="
            f"{runtime.get('classification', 'unknown')} "
            f"qualified={runtime.get('qualified', False)} "
            f"evidence_basis={runtime.get('evidence_basis', 'unknown')}"
        )
    lines.append("-" * 96)
    lines.append(f"{'Check':<32} {'Status':<10} {'Severity':<9} {'Observed'}")
    lines.append("-" * 96)
    for item in report["findings"]:
        observed = item["observed"].replace("\n", " ")[:54]
        lines.append(
            f"{item['check_id']:<32} {item['status']:<10} {item['severity']:<9} {observed}"
        )
    lines.append("-" * 96)
    for item in report["findings"]:
        if item["status"] in {"BLOCKED", "WARN"}:
            lines.append(f"[{item['severity'].upper()}] {item['check_id']}: {item['remediation']}")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[Finding] = []
    findings.extend(check_project())
    findings.extend(check_python())
    findings.extend(check_imports())
    findings.extend(check_pip())
    findings.extend(check_binaries())
    findings.extend(check_toolchain())
    findings.extend(check_oob())
    findings.extend(check_docker(args.docker_config))
    findings.extend(check_sqlite())
    findings.extend(check_rag())
    findings.extend(check_playwright())
    findings.extend(check_llm())
    findings.extend(check_workspace())
    findings.extend(check_ports(args.ports, args.network_checks))
    findings.extend(
        check_redis(os.getenv("REDIS_URL") or os.getenv("WEBPENT_REDIS_URL"), args.network_checks)
    )
    result = [asdict(item) for item in findings]
    runtime_qualification = build_runtime_qualification(result)
    counts = {
        status: sum(1 for item in result if item["status"] == status)
        for status in ("PASS", "WARN", "BLOCKED", "SKIPPED")
    }
    return {
        "schema_version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project_root": str(PROJECT_ROOT),
        "python": sys.version,
        "network_checks_enabled": bool(args.network_checks),
        "llm_probe_performed": False,
        "destructive_actions_performed": False,
        "summary": counts,
        "runtime_qualification": runtime_qualification,
        "findings": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only WebPent runtime diagnostics")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--network-checks",
        action="store_true",
        help="allow localhost/explicit Redis TCP connectivity checks",
    )
    parser.add_argument(
        "--docker-config",
        action="store_true",
        help="run docker compose config --quiet without starting services",
    )
    parser.add_argument(
        "--ports",
        default="",
        help="comma-separated local ports to check only with --network-checks",
    )
    parser.add_argument(
        "--strict", action="store_true", help="return non-zero for warnings as well as blockers"
    )
    args = parser.parse_args(argv)
    try:
        args.ports = [int(value.strip()) for value in args.ports.split(",") if value.strip()]
    except ValueError as exc:
        parser.error(f"invalid --ports value: {exc}")
    report = build_report(args)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report))
    blocked = report["summary"]["BLOCKED"]
    warnings = report["summary"]["WARN"]
    return 1 if blocked or (args.strict and warnings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
