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
