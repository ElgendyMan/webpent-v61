from benchmarks.failure_matrix import run_failure_matrix


def test_failure_matrix_is_offline_and_fail_closed():
    report = run_failure_matrix()
    assert report["mode"] == "offline_failure_injection"
    assert report["network_used"] is False
    assert report["finding_created"] is False
    assert report["invariants"] == {
        "no_network": True,
        "no_finding_promotion": True,
        "scope_denial_is_blocked": True,
        "handler_failure_is_infrastructure_failure": True,
        "missing_evidence_is_not_confirmed": True,
    }


def test_failure_matrix_preserves_dispositions():
    report = run_failure_matrix()
    validator = report["validator_cases"]
    research = report["research_cases"]
    assert validator["reviewable"]["disposition"] == "reviewable"
    assert validator["blocked"]["disposition"] == "blocked"
    assert validator["inconclusive"]["disposition"] == "inconclusive"
    assert validator["missing"]["disposition"] == "inconclusive"
    assert research["scope_denied"]["status"] == "blocked"
    assert research["handler_failure"]["status"] == "infrastructure_failure"
    assert research["success"]["status"] == "negative"
