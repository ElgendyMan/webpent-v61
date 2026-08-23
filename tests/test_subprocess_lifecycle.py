import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.utils.subprocess import run_command


def test_timeout_is_reported_as_tool_execution_error():
    with pytest.raises(ToolExecutionError) as caught:
        run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert caught.value.returncode == -1
    assert "timed out" in str(caught.value).lower()


def test_non_timeout_stderr_is_not_labeled_timeout():
    with pytest.raises(ToolExecutionError) as caught:
        run_command(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('ordinary-error'); sys.exit(3)",
            ],
            timeout=5,
        )
    assert caught.value.returncode == 3
    assert "ordinary-error" in str(caught.value)
    assert "timed out" not in str(caught.value).lower()


def test_parent_termination_does_not_orphan_tool_child(tmp_path: Path):
    pid_file = tmp_path / "child.pid"
    helper = tmp_path / "helper.py"
    child_code = (
        "import os,sys,time; "
        "open(sys.argv[1], 'w').write(str(os.getpid())); "
        "time.sleep(60)"
    )
    helper.write_text(
        "\n".join(
            [
                "import sys, time",
                "from webpent.tools.utils.subprocess import run_command",
                f"run_command([sys.executable, '-c', {child_code!r}, sys.argv[1]], timeout=120)",
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.Popen([sys.executable, str(helper), str(pid_file)])
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.05)
        assert pid_file.exists()
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        proc.kill()
        proc.wait(timeout=5)
        deadline = time.monotonic() + 3
        state_line = ""
        while time.monotonic() < deadline:
            status_path = Path(f"/proc/{child_pid}/status")
            if not status_path.exists():
                break
            state_line = next(
                (
                    line
                    for line in status_path.read_text(encoding="utf-8").splitlines()
                    if line.startswith("State:")
                ),
                "",
            )
            if "\tZ" in state_line or " zombie" in state_line.lower():
                break
            time.sleep(0.05)
        assert (
            not os.path.exists(f"/proc/{child_pid}")
            or "\tZ" in state_line
            or " zombie" in state_line.lower()
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if child_pid and os.path.exists(f"/proc/{child_pid}"):
            os.kill(child_pid, 9)


def test_binary_and_text_output_contracts_remain_compatible():
    assert run_command([sys.executable, "-c", "print('hello')"], timeout=5) == "hello\n"
    assert run_command(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff')"],
        timeout=5,
        binary_output=True,
    ) == b"\xff"
