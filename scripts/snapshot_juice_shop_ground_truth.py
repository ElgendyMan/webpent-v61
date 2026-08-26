#!/usr/bin/env python3
"""Create an independent, metadata-only Juice Shop ground-truth snapshot.

This snapshot is source/catalog consistency evidence, not a vulnerability verdict
and not a P10 approval record. It deliberately stores no response body, headers,
cookies, credentials, or challenge descriptions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from webpent.profiles.juice_shop.cases import JUICE_SHOP_SAFE_CASES


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def git_commit(source_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def live_catalog(origin: str) -> dict[str, object]:
    request = Request(
        origin.rstrip("/") + "/api/Challenges",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read()
            return {
                "available": True,
                "status_code": int(response.status),
                "content_length": len(body),
                "body_sha256": sha256_bytes(body),
                "raw_body_retained": False,
            }
    except (OSError, URLError) as exc:
        return {
            "available": False,
            "status_code": None,
            "content_length": None,
            "body_sha256": None,
            "raw_body_retained": False,
            "failure_type": type(exc).__name__,
        }


def package_version(source_root: Path) -> str | None:
    package_path = source_root / "package.json"
    if not package_path.is_file():
        return None
    package = json.loads(package_path.read_text(encoding="utf-8"))
    value = package.get("version")
    return str(value) if value is not None else None


def source_search_text(source_root: Path) -> str:
    paths = [
        source_root / "server.ts",
        source_root / "routes",
        source_root / "data",
        source_root / "frontend" / "src" / "app",
    ]
    chunks: list[str] = []
    for path in paths:
        members = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        for member in members:
            try:
                chunks.append(member.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return "\n".join(chunks)


def source_support(case: dict[str, object], source_text: str) -> dict[str, object]:
    challenge_key = str(case["challenge_key"])
    path = str(case.get("path") or "")
    return {
        "challenge_key_occurrence_count": source_text.count(challenge_key),
        "path_occurrence_count": source_text.count(path) if path else 0,
        "source_support_is_not_vulnerability_verdict": True,
    }


def source_files(source_root: Path) -> dict[str, str]:
    paths = {
        "challenge_catalog": source_root / "data" / "static" / "challenges.yml",
        "server": source_root / "server.ts",
        "routes_tree": source_root / "routes",
        "search_component": (
            source_root
            / "frontend"
            / "src"
            / "app"
            / "search-result"
            / "search-result.component.ts"
        ),
    }
    digests: dict[str, str] = {}
    for name, path in paths.items():
        if path.is_file():
            digests[name] = file_digest(path)
        elif path.is_dir():
            members = sorted(p for p in path.rglob("*") if p.is_file())
            manifest = "\n".join(
                f"{p.relative_to(source_root)} {file_digest(p)}" for p in members
            ).encode("utf-8")
            digests[name] = sha256_bytes(manifest)
        else:
            digests[name] = "missing"
    return digests


def run(source_root: Path, origin: str, output: Path, run_id: str) -> None:
    source_text = source_search_text(source_root)
    cases = [
        {
            "case_id": case.case_id,
            "challenge_key": case.challenge_key,
            "category": case.category,
            "path": case.path,
            "operation": case.operation,
            "oracle_id": case.oracle_id,
            "mapping_status": case.mapping_status,
            "oracle_status": case.oracle_status,
            "safe_to_execute": case.safe_to_execute,
            "source_ref": case.source_ref,
            "source_support": source_support(
                {
                    "challenge_key": case.challenge_key,
                    "path": case.path,
                },
                source_text,
            ),
        }
        for case in JUICE_SHOP_SAFE_CASES
    ]
    document = {
        "schema_version": "juice_shop.ground_truth.source_catalog_snapshot.v1",
        "snapshot_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "origin": origin,
            "kind": "authorized_local_loopback_lab",
            "source_root": str(source_root),
            "source_commit": git_commit(source_root),
            "package_version": package_version(source_root),
        },
        "independence": {
            "source_is_independent_of_webpent_run_output": True,
            "ground_truth_scope": "source_mapping_and_live_catalog_consistency",
            "source_support_method": "local_source_occurrence_counts_for_challenge_keys_and_paths",
            "vulnerability_verdicts": False,
            "p10_qualification": False,
            "raw_http_data_retained": False,
        },
        "source_file_digests": source_files(source_root),
        "live_catalog": live_catalog(origin),
        "cases": cases,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--origin", default="http://127.0.0.1:3000")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.source_root, args.origin, args.output, args.run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
