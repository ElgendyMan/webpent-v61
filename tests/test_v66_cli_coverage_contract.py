from __future__ import annotations

import json

from typer.testing import CliRunner

from webpent.cli import app

runner = CliRunner()


def test_coverage_command_emits_json_from_state_artifact(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        json.dumps(
            {
                "campaign_ledger": {
                    "entries": [{"id": 1, "key": "idor", "status": "not_scanned"}]
                },
                "proof_outcomes": [
                    {"campaign_key": "idor", "status": "tool_confirmed"}
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["coverage", "--state", str(state_file), "--output", "json"])
    assert result.exit_code == 0
    assert '"confirmed_count": 1' in result.stdout


def test_coverage_command_rejects_unknown_output(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["coverage", "--state", str(state_file), "--output", "yaml"])
    assert result.exit_code == 1
