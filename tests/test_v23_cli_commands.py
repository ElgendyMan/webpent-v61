import json
from pathlib import Path

from typer.testing import CliRunner

from webpent.cli import app

runner = CliRunner()


def test_init_scope_show_and_report_offline(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    result = runner.invoke(app, ["init", "local-lab", "--manifest", str(manifest)])
    assert result.exit_code == 0, result.stdout
    assert manifest.exists()

    result = runner.invoke(
        app,
        [
            "scope",
            "add",
            "https://example.test/items?token=secret&view=full",
            "--manifest",
            str(manifest),
        ],
    )
    assert result.exit_code == 0, result.stdout
    document = json.loads(manifest.read_text())
    assert document["scope"][0]["host"] == "example.test"
    assert "secret" not in manifest.read_text()
    assert "%5BREDACTED%5D" not in manifest.read_text()
    assert "[REDACTED]" in manifest.read_text()

    result = runner.invoke(app, ["scope", "show", "--manifest", str(manifest)])
    assert result.exit_code == 0, result.stdout
    assert "example.test" in result.stdout

    report = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["report", "--manifest", str(manifest), "--format", "json", "--output", str(report)],
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads(report.read_text())["schema_version"] == 1


def test_scope_invalid_url_is_rejected(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    assert runner.invoke(app, ["init", "lab", "--manifest", str(manifest)]).exit_code == 0
    result = runner.invoke(
        app,
        ["scope", "add", "https://user:password@example.test/", "--manifest", str(manifest)],
    )
    assert result.exit_code != 0
    combined_output = (getattr(result, "stdout", "") + getattr(result, "stderr", "")).lower()
    assert "credentials" in combined_output


def test_hunt_is_plan_only_by_default(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    assert runner.invoke(app, ["init", "lab", "--manifest", str(manifest)]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url",
            "https://example.test/",
            "--manifest",
            str(manifest),
            "--time-budget",
            "60",
            "--request-budget",
            "20",
            "--llm-budget",
            "2",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "No network requests were made" in result.stdout
    document = json.loads(manifest.read_text())
    assert document["runs"][0]["status"] == "planned"
    assert document["runs"][0]["request_budget"] == 20


def test_investigate_is_bounded_and_deduplicated(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    assert runner.invoke(app, ["init", "lab", "--manifest", str(manifest)]).exit_code == 0
    args = ["investigate", "finding-1", "--manifest", str(manifest), "--reason", "review evidence"]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0, first.stdout
    assert second.exit_code == 0, second.stdout
    document = json.loads(manifest.read_text())
    assert len(document["investigations"]) == 1
    task = document["investigations"][0]
    assert task["max_depth"] == 1
    assert task["destructive_poc"] is False
    assert task["approval_required"] is True


def test_findings_graph_and_evidence_empty_are_offline_safe(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    assert runner.invoke(app, ["init", "lab", "--manifest", str(manifest)]).exit_code == 0
    for command in ("findings", "evidence"):
        result = runner.invoke(app, [command, "--manifest", str(manifest)])
        assert result.exit_code == 0, result.stdout
    result = runner.invoke(app, ["graph", "summary", "--manifest", str(manifest)])
    assert result.exit_code == 0, result.stdout
    assert '"mental_nodes": 0' in result.stdout


def test_invalid_graph_action_fails_without_touching_manifest(tmp_path: Path):
    manifest = tmp_path / "engagement.json"
    assert runner.invoke(app, ["init", "lab", "--manifest", str(manifest)]).exit_code == 0
    before = manifest.read_text()
    result = runner.invoke(app, ["graph", "delete", "--manifest", str(manifest)])
    assert result.exit_code != 0
    assert manifest.read_text() == before
