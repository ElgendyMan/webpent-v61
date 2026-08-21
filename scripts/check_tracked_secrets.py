"""Fail-closed scan for high-confidence secrets in tracked source/config files."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_PATHS = ("src/", ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
)


def tracked_candidate_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace").strip() or "git ls-files failed")
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8", errors="strict")
        if relative.startswith("src/") or relative.endswith(SENSITIVE_PATHS[1:]):
            paths.append(PROJECT_ROOT / relative)
    return paths


def scan_tracked_secrets() -> list[str]:
    findings: list[str] = []
    for path in tracked_candidate_paths():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                findings.append(f"{path.relative_to(PROJECT_ROOT)}:{line_number}")
    return sorted(findings)


def main() -> int:
    findings = scan_tracked_secrets()
    if findings:
        print("secret scan failed; high-confidence secret patterns found:")
        print("\n".join(findings))
        return 1
    print("secret scan passed: no high-confidence secrets in tracked source/config")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = ["main", "scan_tracked_secrets", "tracked_candidate_paths"]
