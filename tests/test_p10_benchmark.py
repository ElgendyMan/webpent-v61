from webpent.benchmark.p10 import P10GroundTruth, P10Run, evaluate_p10


def _truth(*, approved: bool = True) -> list[P10GroundTruth]:
    categories = [
        "xss",
        "injection",
        "broken access control",
        "security misconfiguration",
        "sensitive data exposure",
        "improper input validation",
    ]
    return [
        P10GroundTruth(
            case_id=f"case-{index}",
            category=categories[index % len(categories)],
            expected=True,
            mapping_status="approved" if approved else "pending_independent_review",
            oracle_status="ready" if approved else "pending_safe_oracle",
        )
        for index in range(10)
    ]


def _run(index: int, *, confirmed: set[str] | None = None, **overrides: object) -> P10Run:
    confirmed = confirmed or set()
    values: dict[str, object] = {
        "run_id": f"run-{index}",
        "workspace_id": f"workspace-{index}",
        "artifact_namespace": f"artifact-{index}",
        "target_ref": "http://127.0.0.1:3000",
        "candidate_case_ids": frozenset(confirmed),
        "proof_case_ids": frozenset(confirmed),
        "replay_case_ids": frozenset(confirmed),
        "target_unchanged": True,
        "findings_are_live": True,
    }
    values.update(overrides)
    return P10Run(**values)


def test_complete_approved_benchmark_calculates_metrics_and_fp_fn() -> None:
    result = evaluate_p10(
        _truth(),
        [
            _run(1, confirmed={"case-0", "case-1", "unknown-case"}),
            _run(2, confirmed={"case-0", "case-1", "unknown-case"}),
            _run(3, confirmed={"case-0", "case-1", "unknown-case"}),
        ],
    )

    assert result["p10_passed"] is True
    assert result["blocking_reasons"] == []
    assert result["metrics"] == {
        "true_positives": 2,
        "false_positives": 1,
        "false_negatives": 8,
        "precision": 0.6667,
        "recall": 0.2,
        "case_coverage": 0.2,
        "class_coverage": 0.3333,
        "false_positive_case_ids": ["unknown-case"],
        "false_negative_case_ids": [
            "case-2",
            "case-3",
            "case-4",
            "case-5",
            "case-6",
            "case-7",
            "case-8",
            "case-9",
        ],
    }


def test_pending_ground_truth_withholds_metrics_fail_closed() -> None:
    result = evaluate_p10(
        _truth(approved=False),
        [_run(1), _run(2), _run(3)],
    )

    assert result["p10_passed"] is False
    assert result["metrics"]["precision"] is None
    assert "approved_ground_truth_cases_below_minimum" in result["blocking_reasons"]
    assert "approved_vulnerability_classes_below_minimum" in result["blocking_reasons"]


def test_duplicate_workspace_and_namespace_block_isolation() -> None:
    result = evaluate_p10(
        _truth(),
        [
            _run(1),
            _run(2, workspace_id="workspace-1"),
            _run(3),
        ],
    )

    assert result["p10_passed"] is False
    assert "workspaces_not_isolated" in result["blocking_reasons"]
    assert result["metrics"]["recall"] is None


def test_live_and_target_safety_are_required_for_every_run() -> None:
    result = evaluate_p10(
        _truth(),
        [
            _run(1),
            _run(2, target_unchanged=False),
            _run(3, findings_are_live=False),
        ],
    )

    assert result["p10_passed"] is False
    assert "target_mutation_detected_or_unproven" in result["blocking_reasons"]
    assert "live_findings_not_proven_for_all_runs" in result["blocking_reasons"]


def test_p10_run_mapping_redacts_and_bounds_untrusted_values() -> None:
    run = P10Run.from_mapping(
        {
            "run_id": " run-1 ",
            "workspace_id": "workspace-1",
            "artifact_namespace": "artifact-1",
            "target_ref": "http://127.0.0.1:3000",
            "candidate_case_ids": ["case-1", "case-1"],
            "proof_case_ids": ["case-1"],
            "replay_case_ids": ["case-1"],
            "target_unchanged": True,
            "findings_are_live": True,
        }
    )

    assert run.run_id == "run-1"
    assert run.confirmed_case_ids == frozenset({"case-1"})
