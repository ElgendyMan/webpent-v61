import importlib.util
import json
from pathlib import Path

_GATE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_vip_quality_gate.py"
_SPEC = importlib.util.spec_from_file_location("run_vip_quality_gate", _GATE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


def _write_artifact(tmp_path: Path, payload: dict) -> None:
    (tmp_path / "juice_shop_p10_evaluation_v1.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_independent_p10_evaluation_missing_artifact_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(_GATE, "DOCS", tmp_path)

    result = _GATE._p10_independent_evaluation_check()

    assert result["passed"] is False
    assert result["returncode"] == 1
    assert "FileNotFoundError" in result["tail"][0]


def test_independent_p10_evaluation_pending_ground_truth_fails_closed(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(_GATE, "DOCS", tmp_path)
    _write_artifact(
        tmp_path,
        {
            "evaluation": {
                "p10_passed": False,
                "run_count": 3,
                "approved_ground_truth_cases": 0,
                "approved_vulnerability_classes": 0,
                "blocking_reasons": ["approved_ground_truth_cases_below_minimum"],
                "metrics": {
                    "precision": None,
                    "recall": None,
                    "class_coverage": None,
                },
            },
            "ground_truth": {
                "independent_review_approved": False,
                "status": "draft_pending_independent_review",
            },
        },
    )

    result = _GATE._p10_independent_evaluation_check()

    assert result["passed"] is False
    assert "not qualified" in result["tail"][0]
    assert "approved_ground_truth_cases_below_minimum" in result["tail"][0]


def test_independent_p10_evaluation_requires_broad_approved_coverage(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(_GATE, "DOCS", tmp_path)
    _write_artifact(
        tmp_path,
        {
            "evaluation": {
                "p10_passed": True,
                "run_count": 3,
                "approved_ground_truth_cases": 9,
                "approved_vulnerability_classes": 6,
                "metrics": {
                    "precision": 1.0,
                    "recall": 1.0,
                    "class_coverage": 1.0,
                },
            },
            "ground_truth": {"independent_review_approved": True},
        },
    )

    result = _GATE._p10_independent_evaluation_check()

    assert result["passed"] is False
    assert "at least ten approved ground-truth cases" in result["tail"][0]


def test_independent_p10_evaluation_accepts_only_complete_contract(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(_GATE, "DOCS", tmp_path)
    _write_artifact(
        tmp_path,
        {
            "evaluation": {
                "p10_passed": True,
                "run_count": 3,
                "approved_ground_truth_cases": 10,
                "approved_vulnerability_classes": 6,
                "metrics": {
                    "precision": 0.9,
                    "recall": 0.8,
                    "class_coverage": 1.0,
                },
            },
            "ground_truth": {"independent_review_approved": True},
        },
    )

    result = _GATE._p10_independent_evaluation_check()

    assert result["passed"] is True
    assert result["returncode"] == 0
