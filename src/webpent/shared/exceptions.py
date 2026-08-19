# src/webpent/shared/exceptions.py
"""webpent.shared.exceptions

Custom exception hierarchy for the WebPent Framework V1.

All framework-raised exceptions descend from :class:`WebPentError` so
that callers can catch the entire family with a single ``except``
clause, while still being able to discriminate by sub-type when finer
handling is required.
"""

from __future__ import annotations

from webpent.shared.redaction import redact_text, redact_value


class WebPentError(Exception):
    """Base class for every exception raised by the WebPent framework.

    Subclass this to create new domain-specific error types so they are
    automatically caught by any ``except WebPentError`` handler.
    """


class ToolNotFoundError(WebPentError):
    """Raised when a required external executable cannot be located.

    Typically indicates a misconfigured ``*_PATH`` setting or a missing
    system dependency. The missing executable name is stored on the
    ``executable`` attribute for diagnostic reporting.
    """

    def __init__(self, executable: str, message: str | None = None) -> None:
        self.executable = executable
        super().__init__(
            message
            or f"Required executable not found on PATH: {executable!r}"
        )


class ToolNotInstalledError(ToolNotFoundError):
    """Raised when an optional exploitation tool is not installed.

    V5 Sprint 6: Semantically distinct from :class:`ToolNotFoundError`
    so callers can distinguish *optional* tools (ysoserial, phpggc —
    whose absence simply degrades a single validator to AI-Assessed)
    from *required* tools (nuclei, dalfox — whose absence aborts a
    whole phase). Inherits from ``ToolNotFoundError`` so existing
    ``except ToolNotFoundError`` handlers continue to catch both.
    """

    def __init__(self, executable: str, message: str | None = None) -> None:
        super().__init__(
            executable,
            message
            or (
                f"Optional exploitation tool not installed: {executable!r}. "
                "Install it to enable this validation path; the finding "
                "will fall back to AI-Assessed."
            ),
        )


class ToolExecutionError(WebPentError):
    """Raised when an external tool exits with a non-zero status.

    Carries the failed command, exit code, and captured stdout/stderr so
    callers can produce rich diagnostic output without re-running the
    tool.
    """

    def __init__(
        self,
        cmd: list[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        message: str | None = None,
    ) -> None:
        safe_cmd = redact_value(cmd)
        safe_stdout = redact_text(stdout) if isinstance(stdout, str) else stdout
        safe_stderr = redact_text(stderr) if isinstance(stderr, str) else stderr
        self.cmd = safe_cmd
        self.returncode = returncode
        self.stdout = safe_stdout
        self.stderr = safe_stderr
        safe_message = redact_text(message) if message else None
        super().__init__(
            safe_message
            or (
                f"Command {safe_cmd!r} failed with exit code {returncode}.\n"
                f"stdout: {safe_stdout}\n"
                f"stderr: {safe_stderr}"
            )
        )
