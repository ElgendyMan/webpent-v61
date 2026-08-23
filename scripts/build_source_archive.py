"""Build a deterministic, source-only WebPent ZIP archive.

The archive intentionally excludes runtime output, logs, historical evidence
bundles, caches, databases, credentials, and repository metadata. It is an
operator delivery artifact, not a replacement for the release manifest.
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from scripts.build_release_manifest import _included

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_EXCLUDED_PREFIXES = (
    "artifacts/",
    "docs/evidence/",
)


def _archive_included(path: Path, root: Path) -> bool:
    if path.is_symlink() or not _included(path):
        return False
    relative = path.relative_to(root).as_posix()
    return not any(
        relative == prefix.rstrip("/") or relative.startswith(prefix)
        for prefix in ARCHIVE_EXCLUDED_PREFIXES
    )


def archive_members(root: Path = PROJECT_ROOT) -> list[tuple[Path, str]]:
    """Return deterministic ``(path, archive-name)`` pairs for a source ZIP."""
    members: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if not _archive_included(path, root):
            continue
        relative = path.relative_to(root).as_posix()
        members.append((path, f"webpent-v61/{relative}"))
    return sorted(members, key=lambda item: item[1])


def build_archive(output: Path, root: Path = PROJECT_ROOT) -> int:
    """Write a reproducible ZIP with fixed member timestamps and permissions."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path, member_name in archive_members(root):
            info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return len(archive_members(root))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    count = build_archive(args.output)
    print(f"created {args.output} with {count} source members")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
