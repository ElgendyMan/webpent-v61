import json

from typer.testing import CliRunner

from webpent.benchmark.qualification import (
    GroundTruthCase,
    QualificationRun,
    build_qualification_matrix,
)
from webpent.cli import app
from webpent.workers.observability import (
    RetryPolicy,
    WorkerObservability,
    celery_reliability_config,
)

runner = CliRunner()


def _manifest(path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engagement": {"name": "contract"},
                "scope": [{"url": "http://127.0.0.1:8000", "host": "127.0.0.1"}],
                "runs": [],
                "findings": [
                    {
                        "id": "f-1",
                        "title": "example",
                        "status": "confirmed",
                        "severity": "high",
                        "confidence": "high",
                        "evidence_refs": ["ev-1"],
                        "causal_signal": True,
                        "negative_control": True,
                    }
                ],
                "evidence_refs": [{"id": "ev-1", "kind": "http", "redacted": True}],
                "target_knowledge": {"engagement_id": "contract", "entities": []},
                "proof_bundles": [
                    {"id": "pb-1", "evidence_id": "ev-1", "sealed": True, "replay_matches": True}
                ],
            }
        ),
        encoding="utf-8",
    )


def test_qualification_matrix_is_deterministic_and_safe() -> None:
    matrix = build_qualification_matrix(
        [GroundTruthCase("x", "access-control")],
        [QualificationRun("r1", "fixture", "artifact.json", ("x",), target_modified=False)],
    )
    summary = matrix.summary()
    assert summary["coverage"] == 1.0
    assert summary["all_runs_target_unchanged"] is True
    assert summary["live_qualification_proven"] is False


def test_qualification_rejects_duplicate_run_ids() -> None:
    matrix = build_qualification_matrix([], [])
    run = QualificationRun("r1", "fixture", "artifact.json")
    matrix.add_run(run)
    try:
        matrix.add_run(run)
    except ValueError as exc:
        assert "duplicate run_id" in str(exc)
    else:
        raise AssertionError("duplicate run id was accepted")


def test_worker_observability_redacts_payload_and_bounds_events() -> None:
    observer = WorkerObservability(max_events=1, retry_policy=RetryPolicy(max_retries=1))
    observer.record("started", task_name="scan", task_id="t1", payload="secret")
    observer.record("finished", task_name="scan", task_id="t2", args={"password": "secret"})
    dead = observer.record_dead_letter(
        task_name="scan", task_id="t2", retries=4, reason="failed", payload={"password": "secret"}
    )
    snapshot = observer.snapshot()
    assert len(snapshot["events"]) == 1
    assert "payload" not in snapshot["events"][0]
    assert "args" not in snapshot["events"][0]
    assert dead.payload_sha256
    assert "secret" not in json.dumps(snapshot)
    assert snapshot["qualified_live_broker"] is False


def test_celery_reliability_config_is_explicit_about_unqualified_dlq() -> None:
    config = celery_reliability_config()
    assert config["task_reject_on_worker_lost"] is True
    assert config["webpent_dlq_queue"] == "webpent.dlq"
    assert config["webpent_dlq_qualified"] is False


def test_analyze_knowledge_replay_and_explain_are_local_read_only_commands(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    _manifest(manifest)
    analyze = runner.invoke(app, ["analyze", "--artifact", str(manifest), "--output", "json"])
    assert analyze.exit_code == 0
    assert '"confirmed": 1' in analyze.stdout

    knowledge = runner.invoke(app, ["knowledge", "--artifact", str(manifest), "--output", "json"])
    assert knowledge.exit_code == 0
    assert '"engagement_id": "contract"' in knowledge.stdout

    replay = runner.invoke(app, ["replay", "--artifact", str(manifest), "--output", "json"])
    assert replay.exit_code == 0
    assert '"live_replay_performed": false' in replay.stdout

    explain = runner.invoke(
        app, ["explain", "f-1", "--artifact", str(manifest), "--output", "json"]
    )
    assert explain.exit_code == 0
    assert '"authority": "read_only_explanation"' in explain.stdout


def test_campaign_requires_existing_scope_and_records_only_a_plan(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    _manifest(manifest)
    result = runner.invoke(
        app,
        [
            "campaign",
            "--target-ref",
            "http://127.0.0.1:8000",
            "--manifest",
            str(manifest),
        ],
    )
    assert result.exit_code == 0
    document = json.loads(manifest.read_text(encoding="utf-8"))
    assert document["runs"][0]["status"] == "planned"
    assert document["runs"][0]["execution_required"] is True


def test_campaign_rejects_out_of_scope_target_without_network(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    _manifest(manifest)
    result = runner.invoke(
        app,
        ["campaign", "--target-ref", "http://outside.invalid", "--manifest", str(manifest)],
    )
    assert result.exit_code == 1
    document = json.loads(manifest.read_text(encoding="utf-8"))
    assert document["runs"] == []
