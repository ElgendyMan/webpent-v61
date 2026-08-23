from pathlib import Path

from scripts.audit_superagentic_wiring import _calls


def test_wiring_audit_counts_action_executor_only(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "\n".join(
            [
                "def run(conn, runtime, executor):",
                "    conn.execute('select 1')",
                "    runtime.action_executor.execute(task, handler)",
                "    executor.execute(task, handler)",
                "    runtime.run_agent_proposal(proposal)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    counts = _calls(source)

    assert counts == {
        "direct_executor_calls": 2,
        "run_agent_proposal_calls": 1,
    }



def test_wiring_audit_is_fail_closed_on_parse_error(tmp_path: Path) -> None:
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")

    counts = _calls(source)

    assert counts["parse_error"] == 1
    assert "parse_error_text" in counts
