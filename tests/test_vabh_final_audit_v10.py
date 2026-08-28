from webpent.vabhfqr_v10 import (
    AuditStatus,
    ImplementationStatus,
    build_project_state_report,
    build_scorecard,
    gap,
    weighted_readiness,
)


def _capabilities(score: float = 100.0) -> dict[str, dict[str, object]]:
    names = (
        "autonomous_research_loop",
        "target_intelligence",
        "security_reasoning",
        "attack_graph",
        "hypothesis_generation",
        "research_planning",
        "adaptive_strategy",
        "memory_and_learning",
        "evidence_pipeline",
        "causal_validation",
        "proofbundle_integrity",
        "replay_capability",
        "benchmark_framework",
        "metrics_system",
        "governance_boundaries",
    )
    return {
        name: {
            "status": AuditStatus.PASS,
            "maturity_score": score,
            "evidence_refs": (f"tests/{name}",),
        }
        for name in names
    }


def _report(score: float = 100.0):
    return build_project_state_report(
        repository="WebPent",
        commit="abc123",
        branch_parity=True,
        working_tree_clean=True,
        inventory={"source": 1, "tests": 1},
        capability_values=_capabilities(score),
        gaps=(
            gap(
                "EXT-001",
                "target-backed-causal-evidence",
                "HIGH",
                "qualification metrics remain unavailable",
                "Run only after formal authorization and valid ground truth.",
                internal=False,
                status=ImplementationStatus.EXTERNAL,
            ),
        ),
        technical_debt=("historical reports require archival labeling",),
        risks=("qualification evidence is absent",),
        test_summary={"focused": "PASS"},
        governance={"vip_qualified": False, "p10_opened": False},
        remaining_external_requirements=("human signoff",),
    )


def test_weighted_readiness_is_bounded_and_deterministic():
    report = _report()
    assert report.readiness_percentage == 100.0
    assert weighted_readiness(report.capabilities) == 100.0
    assert tuple(item.capability for item in report.capabilities) == tuple(_capabilities())


def test_scorecard_is_advisory_and_does_not_grant_qualification():
    report = _report()
    scorecard = build_scorecard(
        report,
        blockers=("no approved official runs",),
        external_requirements=("3 isolated official runs",),
    )
    assert scorecard.engineering_readiness_percentage == 100.0
    assert scorecard.official_qualification == "NOT_QUALIFIED"
    assert scorecard.advisory_only is True
    assert scorecard.vip_qualified is False
    assert scorecard.p10_completed is False


def test_partial_capability_is_preserved_as_partial():
    values = _capabilities()
    values["causal_validation"] = {
        "status": AuditStatus.BLOCKED,
        "maturity_score": 0.0,
        "limitation": "no target-backed causal observations",
    }
    report = build_project_state_report(
        repository="WebPent",
        commit="abc123",
        branch_parity=True,
        working_tree_clean=True,
        inventory={},
        capability_values=values,
        gaps=(),
        technical_debt=(),
        risks=(),
        test_summary={},
        governance={"vip_qualified": False},
        remaining_external_requirements=(),
    )
    causal = next(item for item in report.capabilities if item.capability == "causal_validation")
    assert causal.status is AuditStatus.BLOCKED
    assert causal.maturity_score == 0.0
    assert report.readiness_percentage < 100.0


def test_metrics_require_explicit_agreement_and_never_promote_blocked():
    from webpent.vabhfqr_v10 import compute_classification_metrics

    result = compute_classification_metrics(
        {
            "case-tp": ("TP", "TP"),
            "case-tn": ("TN", "TN"),
            "case-fp": ("FP", "FP"),
            "case-fn": ("FN", "FN"),
        }
    )
    assert result.valid is True
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.f1 == 0.5

    blocked = compute_classification_metrics({"case-blocked": ("TP", "BLOCKED")})
    assert blocked.valid is False
    assert blocked.precision is None
    assert blocked.recall is None
    assert blocked.f1 is None


def test_metrics_reject_label_disagreement_instead_of_inventing_counts():
    from webpent.vabhfqr_v10 import compute_classification_metrics

    result = compute_classification_metrics({"case-unknown": ("TP", "TN")})
    assert result.valid is False
    assert result.true_positives == 0
    assert result.reason == "label_disagreement:case-unknown"
