"""Schemas for bounded, evidence-backed campaign qualification.

These records describe what a qualification run measured.  They do not claim
that a live lab was tested; callers must provide explicit run evidence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class GroundTruthCase:
    """One expected vulnerability class or case in a controlled fixture."""

    case_id: str
    category: str
    expected: bool = True
    source: str = "operator-declared"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class QualificationRun:
    """A single run result tied to one explicit target and evidence artifact."""

    run_id: str
    target_ref: str
    evidence_artifact: str
    confirmed_case_ids: tuple[str, ...] = ()
    reviewed_case_ids: tuple[str, ...] = ()
    contacted_target: bool = False
    target_modified: bool = False
    findings_are_live: bool = False

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["confirmed_case_ids"] = list(self.confirmed_case_ids)
        result["reviewed_case_ids"] = list(self.reviewed_case_ids)
        return result


@dataclass
class QualificationMatrix:
    """Deterministic multi-run qualification projection."""

    ground_truth: list[GroundTruthCase] = field(default_factory=list)
    runs: list[QualificationRun] = field(default_factory=list)

    def add_run(self, run: QualificationRun) -> None:
        if any(existing.run_id == run.run_id for existing in self.runs):
            raise ValueError(f"duplicate run_id: {run.run_id}")
        self.runs.append(run)

    def summary(self) -> dict[str, Any]:
        expected = {case.case_id for case in self.ground_truth if case.expected}
        confirmed = {
            case_id
            for run in self.runs
            for case_id in run.confirmed_case_ids
            if case_id in expected
        }
        run_safety = all(not run.target_modified for run in self.runs)
        return {
            "ground_truth_cases": len(expected),
            "runs": len(self.runs),
            "confirmed_expected_cases": len(confirmed),
            "coverage": round(len(confirmed) / len(expected), 4) if expected else 0.0,
            "all_runs_target_unchanged": run_safety,
            "live_qualification_proven": all(run.findings_are_live for run in self.runs)
            if self.runs
            else False,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "ground_truth": [case.as_dict() for case in self.ground_truth],
            "runs": [run.as_dict() for run in self.runs],
            "summary": self.summary(),
        }


def build_qualification_matrix(
    ground_truth: Iterable[GroundTruthCase], runs: Iterable[QualificationRun]
) -> QualificationMatrix:
    matrix = QualificationMatrix(ground_truth=list(ground_truth))
    for run in runs:
        matrix.add_run(run)
    return matrix


__all__ = [
    "GroundTruthCase",
    "QualificationMatrix",
    "QualificationRun",
    "build_qualification_matrix",
]
