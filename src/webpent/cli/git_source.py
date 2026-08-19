"""Safe, shallow Git source acquisition for the ingest CLI."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

_MAX_CLONE_TIMEOUT_SECONDS = 300


class GitSourceError(RuntimeError):
    """Raised when a Git source cannot be validated or cloned."""


def validate_git_url(repo_url: str) -> str:
    """Validate and normalize a public HTTPS Git URL.

    The ingest wrapper deliberately does not accept shell-style SSH URLs or
    embedded credentials. This keeps the command predictable and prevents
    credentials from being copied into subprocess arguments or logs.
    """
    value = str(repo_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise GitSourceError("Only HTTPS Git URLs with a hostname are supported")
    if parsed.username or parsed.password:
        raise GitSourceError("Git URLs containing embedded credentials are not allowed")
    if parsed.fragment:
        raise GitSourceError("Git URL fragments are not supported")
    return value


def clone_repository(
    repo_url: str,
    destination: Path,
    *,
    git_ref: str | None = None,
    timeout_seconds: int = _MAX_CLONE_TIMEOUT_SECONDS,
) -> Path:
    """Clone one repository shallowly and return its checkout path.

    The destination must not already exist. The subprocess is invoked without
    a shell, terminal prompts are disabled, tags are omitted, and checkout
    hooks are disabled for this data-ingestion-only operation.
    """
    url = validate_git_url(repo_url)
    if git_ref is not None and (not git_ref.strip() or git_ref.lstrip().startswith("-")):
        raise GitSourceError("Git ref must be a non-empty name and cannot start with '-'")

    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise GitSourceError(f"Clone destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--config",
        "core.hooksPath=/dev/null",
    ]
    if git_ref:
        command.extend(["--branch", git_ref.strip()])
    command.extend(["--", url, str(destination)])

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise GitSourceError(
            f"Git clone timed out after {timeout_seconds} seconds"
        ) from exc
    except OSError as exc:
        raise GitSourceError(f"Could not start git: {exc}") from exc

    if completed.returncode != 0:
        if destination.exists():
            import shutil

            shutil.rmtree(destination, ignore_errors=True)
        detail = (completed.stderr or completed.stdout or "git clone failed").strip()
        raise GitSourceError(f"Git clone failed: {detail[-1000:]}")
    return destination
