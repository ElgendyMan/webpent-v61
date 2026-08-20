from __future__ import annotations

from pathlib import Path

from scripts import run_vip_quality_gate


def test_quality_gate_prefers_project_venv_tools_when_available() -> None:
    tools_dir = run_vip_quality_gate.PROJECT_ROOT / ".venv" / "bin"

    for tool, resolved_value in (
        ("ruff", run_vip_quality_gate.RUFF),
        ("bandit", run_vip_quality_gate.BANDIT),
        ("pip-audit", run_vip_quality_gate.PIP_AUDIT),
    ):
        project_tool = tools_dir / tool
        if project_tool.is_file():
            assert Path(resolved_value).resolve() == project_tool.resolve()
        else:
            assert Path(resolved_value).name == tool
