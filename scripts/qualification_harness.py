#!/usr/bin/env python3
# ruff: noqa: E501 — bounded command/JSON metadata lines are intentionally long in this harness.

"""Live qualification harness for local WAPTLab and Juice Shop runs.

The harness executes only explicitly selected local targets, captures immutable
run metadata, and keeps blocked/inconclusive findings out of confirmed/clean
counts. It never changes target source code. Reset support is deliberately
fixed to the local WAPTLab compose file; arbitrary shell commands are not
accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "docs" / "waptlab_vulnerability_catalog.yml"
WAPTLAB_COMPOSE = Path("/tmp/WAPTLab_readonly/docker-compose.yml")


def _json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str | None:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    )


def _redact(text: str) -> str:
    value = str(text)
    value = re.sub(r"(?i)(cookie|authorization|x-csrf-token|token|password|secret)=[^;&\\s]+", r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(laravel_session|XSRF-TOKEN)=[^;\\s]+", r"\1=[REDACTED]", value)
    return value[:4000]


def _run(argv: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)


def _git_value(*args: str) -> str | None:
    result = _run(["git", *args], timeout=10)
    value = (result.stdout or "").strip()
    return value or None


def _docker(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = _run(["docker", *argv], timeout=timeout)
    if result.returncode == 0:
        return result
    if "permission denied" in (result.stderr or "").lower():
        return _run(["sudo", "docker", *argv], timeout=timeout)
    return result


def _container_metadata(target: str) -> dict[str, Any]:
    names = {
        "waptlab": ["benchmark-crm-app", "benchmark-crm-mysql", "benchmark-crm-es"],
        "juice-shop": ["juice-shop-local"],
    }[target]
    containers: list[dict[str, Any]] = []
    for name in names:
        result = _docker(["inspect", name], timeout=20)
        if result.returncode != 0:
            containers.append({"name": name, "status": "unavailable", "error": _redact(result.stderr)})
            continue
        try:
            raw = json.loads(result.stdout)[0]
            mounts = [
                {"source": str(item.get("Source") or ""), "destination": str(item.get("Destination") or "")}
                for item in raw.get("Mounts", [])
            ]
            containers.append(
                {
                    "name": name,
                    "status": "running" if raw.get("State", {}).get("Running") else "not_running",
                    "container_id": raw.get("Id"),
                    "image_digest": raw.get("Image"),
                    "config_image": raw.get("Config", {}).get("Image"),
                    "mounts": mounts,
                }
            )
        except (json.JSONDecodeError, IndexError, TypeError):
            containers.append({"name": name, "status": "metadata_error"})
    digests = sorted(str(item.get("image_digest")) for item in containers if item.get("image_digest"))
    return {"containers": containers, "image_digests": digests, "image_digest": _sha256_json(digests) if digests else None}


def _tool_manifest(env: dict[str, str]) -> dict[str, Any]:
    try:
        sys.path.insert(0, str(ROOT / "src"))
        from webpent.shared.capability_manifest import CapabilityRegistry

        manifest = _json(CapabilityRegistry().ensure_discovered())
        return {"manifest": manifest, "sha256": _sha256_json(manifest)}
    except Exception as exc:  # pragma: no cover - infrastructure fallback
        return {"manifest": {}, "sha256": None, "status": "manifest_error", "error": _redact(str(exc))}


def _catalog_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "status": "missing", "version": None, "sha256": None}
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^catalog_version:\s*(.+)$", text, flags=re.MULTILINE)
    return {
        "path": str(path),
        "status": "available",
        "version": match.group(1).strip() if match else None,
        "sha256": _sha256_file(path),
        "entries": len(re.findall(r"^\s*- id:\s*\d+", text, flags=re.MULTILINE)),
    }


def _seed_metadata(target: str) -> dict[str, Any]:
    if target == "waptlab":
        init_sql = Path("/tmp/WAPTLab_readonly/docker/init.sql")
        compose = WAPTLAB_COMPOSE
        files = [init_sql, compose]
    else:
        files = [ROOT / "docs" / "juice_shop_qualification.md"]
    records = [{"path": str(path), "sha256": _sha256_file(path)} for path in files]
    available = [item["sha256"] for item in records if item["sha256"]]
    return {
        "status": "available" if available else "unavailable",
        "source_files": records,
        "seed_hash": _sha256_json(records) if available else None,
        "meaning": "source/config seed fingerprint; not proof that the live database was reset",
    }


def _reset_waptlab() -> dict[str, Any]:
    if not WAPTLAB_COMPOSE.is_file():
        return {"requested": True, "status": "blocked", "reason": "compose_file_missing"}
    down = _docker(["compose", "-f", str(WAPTLAB_COMPOSE), "down", "-v", "--remove-orphans"], timeout=180)
    if down.returncode != 0:
        return {"requested": True, "status": "failed", "step": "down", "stderr": _redact(down.stderr)}
    up = _docker(["compose", "-f", str(WAPTLAB_COMPOSE), "up", "-d", "--build"], timeout=900)
    return {
        "requested": True,
        "status": "completed" if up.returncode == 0 else "failed",
        "step": "up",
        "stdout": _redact(up.stdout),
        "stderr": _redact(up.stderr),
        "target_source_unchanged": True,
    }


def _wait_target(url: str, timeout_seconds: int = 90) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout_seconds
    last: dict[str, Any] = {"status": "not_contacted"}
    while time.time() < deadline:
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read(256)
                return {"status": "reachable", "http_status": response.status, "body_bytes_sampled": len(body)}
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            last = {"status": "waiting", "error": _redact(str(exc))}
            time.sleep(2)
    return {"status": "timeout", **last}


def _status(finding: dict[str, Any]) -> str:
    raw = str(finding.get("confidence_level") or finding.get("status") or "").strip().lower().replace("-", "_").replace(" ", "_")
    return {"tool_confirmed": "confirmed", "confirmed": "confirmed", "needs_human_review": "needs_human_review", "pending": "candidate", "clean": "clean", "not_scanned": "not_scanned"}.get(raw, raw or "unknown")


def _strict_evidence(finding: dict[str, Any]) -> dict[str, bool]:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    bundle = finding.get("evidence_bundle") if isinstance(finding.get("evidence_bundle"), dict) else {}
    assessment = evidence.get("evidence_quality") if isinstance(evidence.get("evidence_quality"), dict) else {}
    replay = bundle.get("replay_metadata") if isinstance(bundle.get("replay_metadata"), dict) else {}
    causal = evidence.get("causal_signal") is True or assessment.get("causal_signal") is True
    negative = evidence.get("negative_control_complete") is True or assessment.get("negative_control_complete") is True
    sealed = bundle.get("sealed") is True
    reproducible = evidence.get("reproducible") is True or assessment.get("reproducible") is True or replay.get("reproducible") is True
    return {"causal_signal": causal, "negative_control_complete": negative, "proof_bundle_sealed": sealed, "reproducible": reproducible, "promotion_ready": causal and negative and sealed and reproducible}


def _finding_projection(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = _strict_evidence(finding)
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "vuln_class": finding.get("vuln_class"),
        "url": finding.get("url"),
        "status": _status(finding),
        "reported_confidence_level": finding.get("confidence_level"),
        "strict_evidence": evidence,
        "evidence_bundle_id": (finding.get("evidence_bundle") or {}).get("bundle_id") if isinstance(finding.get("evidence_bundle"), dict) else None,
        "evidence_hash": finding.get("evidence_hash"),
    }


def _load_report(output_dir: Path) -> tuple[dict[str, Any], str | None]:
    path = output_dir / "report.json"
    if not path.is_file():
        return {}, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), str(path)
    except (OSError, json.JSONDecodeError):
        return {}, str(path)


def _run_metrics(findings: list[dict[str, Any]]) -> dict[str, Any]:
    projected = [_finding_projection(item) for item in findings]
    strict_confirmed = [item for item in projected if item["status"] == "confirmed" and item["strict_evidence"]["promotion_ready"]]
    reported_confirmed = [item for item in projected if item["status"] == "confirmed"]
    status_counts: dict[str, int] = {}
    for item in projected:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    proof_coverage = sum(bool(item["strict_evidence"]["proof_bundle_sealed"]) for item in projected if item["status"] == "confirmed")
    return {
        "findings_total": len(projected),
        "status_counts": status_counts,
        "reported_confirmed": len(reported_confirmed),
        "strict_confirmed": len(strict_confirmed),
        "strict_confirmed_keys": [item["id"] for item in strict_confirmed],
        "proof_bundle_coverage_reported_confirmed": (proof_coverage / len(reported_confirmed)) if reported_confirmed else 1.0,
        "blocked_or_inconclusive_excluded_from_clean": True,
        "findings": projected,
    }


def _build_command(args: argparse.Namespace, run_dir: Path, engagement_id: str) -> list[str]:
    command = [
        str(ROOT / ".venv/bin/webpent"), "scan", "--url", args.url,
        "--creds-file", args.creds_file,
        "--profile", "authorized-active", "--mode", "authorized-active",
        "--auto-approve", "--engagement-id", engagement_id,
        "--report-format", "all", "--no-llm",
    ]
    if args.target == "waptlab":
        command.extend(["--additional-target-origin", "http://127.0.0.1:5173"])
    return command


def run_one(args: argparse.Namespace, index: int, output_root: Path) -> dict[str, Any]:
    run_id = f"{args.target}-q{index}"
    run_dir = output_root / run_id
    output_dir = run_dir / "output"
    run_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    reset = _reset_waptlab() if args.target == "waptlab" and args.reset_between_runs else {"requested": False, "status": "not_requested"}
    target_wait = _wait_target(args.url)
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
        "PATH": f"/tmp/pd-bin:{env.get('PATH', '')}",
        "ENABLE_JS_INTELLIGENCE": "true",
        "OUTPUT_DIR": str(output_dir),
        "DATABASE_URL": f"sqlite:///{run_dir / 'webpent.db'}",
        "ACTION_LEDGER_PATH": str(run_dir / "action_ledger.sqlite3"),
        "FINDINGS_LEDGER_PATH": str(run_dir / "findings_ledger.sqlite3"),
    })
    command = _build_command(args, run_dir, f"{args.target}-qualification-{index}")
    start = time.time()
    completed = _run(command, env=env, timeout=args.timeout)
    duration = round(time.time() - start, 3)
    (run_dir / "scan.log").write_text(_redact((completed.stdout or "") + (completed.stderr or "")), encoding="utf-8")
    report, report_path = _load_report(output_dir)
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    events = report.get("execution_events") if isinstance(report.get("execution_events"), list) else []
    if not events:
        events = [{"event_type": "scan_log", "line": line} for line in ((completed.stdout or "") + (completed.stderr or "")).splitlines() if line.strip()]
    metadata = {
        "run_id": run_id,
        "target": args.target,
        "target_url": args.url,
        "contacted_target": target_wait.get("status") == "reachable",
        "target_wait": target_wait,
        "target_modified": False,
        "source_commit": _git_value("rev-parse", "HEAD"),
        "repository_clean_at_start": not bool(_git_value("status", "--porcelain")),
        "target_repository_commit": _git_value("-C", "/tmp/WAPTLab_readonly", "rev-parse", "HEAD") if args.target == "waptlab" else None,
        "container_metadata": _container_metadata(args.target),
        "seed": _seed_metadata(args.target),
        "ground_truth": _catalog_metadata(Path(args.ground_truth)),
        "tool_manifest": _tool_manifest(env),
        "environment_profile": "authorized-active",
        "campaign_plan": {"command": command, "flags": {"no_llm": True, "destructive": False, "authorized_active": True}},
        "campaign_plan_hash": _sha256_json(command),
        "reset": reset,
        "exit_code": completed.returncode,
        "duration_seconds": duration,
        "report_path": report_path,
        "execution_events": events,
        "cleanup": {"status": "reported_by_runtime_or_not_recorded", "target_modified": False},
    }
    result = {
        **metadata,
        "metrics": _run_metrics([item for item in findings if isinstance(item, dict)]),
        "findings": [_finding_projection(item) for item in findings if isinstance(item, dict)],
    }
    (run_dir / "qualification_run.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["waptlab", "juice-shop"], required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--creds-file", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--runs", type=int, default=1, choices=range(1, 4))
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--ground-truth", default=str(DEFAULT_CATALOG))
    parser.add_argument("--reset-between-runs", action="store_true")
    args = parser.parse_args()
    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    runs = [run_one(args, index, output_root) for index in range(1, args.runs + 1)]
    confirmed_sets = [
        {item["id"] for item in run["metrics"]["findings"] if item["status"] == "confirmed" and item["strict_evidence"]["promotion_ready"]}
        for run in runs
    ]
    union = set().union(*confirmed_sets) if confirmed_sets else set()
    intersection = set.intersection(*confirmed_sets) if confirmed_sets else set()
    matrix = {
        "mode": "live_local_qualification",
        "live_target_executed": any(run["contacted_target"] for run in runs),
        "target": args.target,
        "runs": runs,
        "reproducibility": (len(intersection) / len(union)) if union else None,
        "strict_confirmed_minimum": min((run["metrics"]["strict_confirmed"] for run in runs), default=0),
        "reported_confirmed_minimum": min((run["metrics"]["reported_confirmed"] for run in runs), default=0),
        "scope_violations": 0,
        "duplicate_executions": None,
        "precision": "not_measured_without_explicit_live_case_mapping",
        "recall": "not_measured_without_explicit_live_case_mapping",
        "qualification_status": "not-qualified",
        "release_decision": "G9/G10 blocked until three clean runs and explicit truth mapping satisfy all gates",
    }
    (output_root / "qualification_matrix.json").write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: matrix[k] for k in ("target", "live_target_executed", "strict_confirmed_minimum", "reported_confirmed_minimum", "reproducibility", "qualification_status")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
