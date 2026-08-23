from webpent.shared.exploration import CapabilityAwarePlanner, CoverageMatrix, WorkflowExplorer
from webpent.shared.governed_artifacts import Hypothesis, WorkflowModel


def test_capability_planner_returns_explicit_gaps_without_fallback_execution() -> None:
    hypotheses = (
        Hypothesis("h1", "xss", "test reflection", required_capabilities=("http_read",)),
        Hypothesis("h2", "ssrf", "test callback", required_capabilities=("oob_observe",)),
    )
    plans, gaps = CapabilityAwarePlanner().plan(
        hypotheses,
        available_capabilities=("http_read",),
        attempted_by_class={"xss": 0},
    )
    assert [item.hypothesis_id for item in plans] == ["h1"]
    assert gaps[0].hypothesis_id == "h2"
    assert gaps[0].missing_capabilities == ("oob_observe",)


def test_coverage_matrix_is_target_package_scoped() -> None:
    matrix = CoverageMatrix("eng-1", "sha256:target-1")
    matrix.record_attempt("xss")
    matrix.record_attempt("xss", confirmed=True)
    snapshot = matrix.snapshot()
    assert snapshot["engagement_id"] == "eng-1"
    assert snapshot["target_package_digest"] == "sha256:target-1"
    assert snapshot["attempts"] == {"xss": 2}
    assert snapshot["confirmed_classes"] == ["xss"]


def test_workflow_explorer_is_bounded_and_never_executes_transitions() -> None:
    model = WorkflowModel(
        workflow_id="wf-1",
        states=("anonymous", "authenticated", "complete"),
        transitions=(
            ("anonymous", "login", "authenticated"),
            ("authenticated", "submit", "complete"),
            ("unknown", "bad", "complete"),
            ("anonymous", "login", "authenticated"),
        ),
        current_state="anonymous",
    )
    steps = WorkflowExplorer().explore(model, max_steps=1)
    assert len(steps) == 1
    assert steps[0].status == "unattempted"
