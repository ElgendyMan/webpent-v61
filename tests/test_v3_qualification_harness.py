from scripts.qualification_harness import _run_metrics, _strict_evidence


def _finding(*, status="Tool-Confirmed", evidence=None, bundle=None):
    return {
        "id": "finding-1",
        "title": "synthetic finding",
        "url": "http://127.0.0.1/test",
        "vuln_class": "idor",
        "confidence_level": status,
        "evidence": evidence or {},
        "evidence_bundle": bundle or {},
    }


def test_harness_keeps_reported_confirmation_separate_from_strict_confirmation():
    finding = _finding(
        evidence={"causal_signal": True, "negative_control_complete": True, "reproducible": True},
        bundle={"sealed": True},
    )
    assert _strict_evidence(finding)["promotion_ready"] is True
    metrics = _run_metrics([finding])
    assert metrics["reported_confirmed"] == 1
    assert metrics["strict_confirmed"] == 1


def test_harness_does_not_promote_without_negative_control_or_replay():
    finding = _finding(
        evidence={"causal_signal": True},
        bundle={"sealed": True},
    )
    assert _strict_evidence(finding)["promotion_ready"] is False
    metrics = _run_metrics([finding])
    assert metrics["reported_confirmed"] == 1
    assert metrics["strict_confirmed"] == 0


def test_harness_keeps_needs_review_and_clean_out_of_confirmed():
    metrics = _run_metrics(
        [
            _finding(status="Needs Human Review"),
            _finding(status="Clean"),
        ]
    )
    assert metrics["findings_total"] == 2
    assert metrics["reported_confirmed"] == 0
    assert metrics["strict_confirmed"] == 0
    assert metrics["status_counts"] == {"needs_human_review": 1, "clean": 1}


def test_harness_loads_unique_run_local_workspace_report_and_rejects_ambiguity(tmp_path):
    from scripts.qualification_harness import _load_report

    output_dir = tmp_path / "output"
    workspace_root = tmp_path / "target_workspaces"
    report_dir = workspace_root / "workspace-1" / "reports"
    report_dir.mkdir(parents=True)
    report_path = report_dir / "report.json"
    report_path.write_text('{"findings": []}', encoding="utf-8")

    report, loaded_path = _load_report(output_dir, workspace_root=workspace_root)
    assert report == {"findings": []}
    assert loaded_path == str(report_path)

    second = workspace_root / "workspace-2" / "reports" / "report.json"
    second.parent.mkdir(parents=True)
    second.write_text('{"findings": [1]}', encoding="utf-8")
    assert _load_report(output_dir, workspace_root=workspace_root) == ({}, None)


def test_harness_does_not_guess_malformed_workspace_report(tmp_path):
    workspace_root = tmp_path / "target_workspaces" / "workspace-1" / "reports"
    workspace_root.mkdir(parents=True)
    (workspace_root / "report.json").write_text("not-json", encoding="utf-8")

    from scripts.qualification_harness import _load_report

    report, loaded_path = _load_report(
        tmp_path / "output", workspace_root=tmp_path / "target_workspaces"
    )
    assert report == {}
    assert loaded_path == str(workspace_root / "report.json")


__all__ = [
    "test_harness_loads_unique_run_local_workspace_report_and_rejects_ambiguity",
    "test_harness_does_not_guess_malformed_workspace_report",
]



def test_harness_passes_cookie_file_path_without_cookie_contents(tmp_path):
    from argparse import Namespace

    from scripts.qualification_harness import _build_command

    args = Namespace(
        target="waptlab",
        url="http://127.0.0.1:8000",
        creds_file="/tmp/empty-creds.json",
        cookie_file="/tmp/wapt_owner_cookies.json",
    )
    command = _build_command(args, tmp_path, "waptlab-qualification-1")
    assert "--cookie-file" in command
    assert "/tmp/wapt_owner_cookies.json" in command
    assert "laravel_session" not in " ".join(command)
