from __future__ import annotations

from pathlib import Path

from webpent.shared.p9_qualification import P9QualificationLedger


def test_p9_qualification_side_effect_is_recorded_once(tmp_path: Path) -> None:
    ledger = P9QualificationLedger(tmp_path / "p9.sqlite3")

    first = ledger.begin_or_resume("engagement-a", "run-a", "worker-a")
    second = ledger.begin_or_resume("engagement-a", "run-a", "worker-b")

    assert first.checkpoint_created is True
    assert second.checkpoint_created is True
    assert first.side_effect_count == 0
    assert second.side_effect_count == 0
    assert ledger.record_side_effect("engagement-a", "run-a", "worker-a") is True
    assert ledger.record_side_effect("engagement-a", "run-a", "worker-b") is False
    assert ledger.complete("engagement-a", "run-a") is True
    assert ledger.complete("engagement-a", "run-a") is False

    final = ledger.get("engagement-a", "run-a")
    assert final is not None
    assert final.status == "completed"
    assert final.side_effect_count == 1
    assert final.worker_id == "worker-a"
    assert ledger.output_digest("engagement-a", "run-a")


def test_p9_qualification_runs_are_scoped_by_engagement(tmp_path: Path) -> None:
    ledger = P9QualificationLedger(tmp_path / "p9.sqlite3")

    ledger.begin_or_resume("engagement-a", "same-key", "worker-a")
    ledger.begin_or_resume("engagement-b", "same-key", "worker-b")
    assert ledger.record_side_effect("engagement-a", "same-key", "worker-a") is True
    assert ledger.record_side_effect("engagement-b", "same-key", "worker-b") is True

    first = ledger.get("engagement-a", "same-key")
    second = ledger.get("engagement-b", "same-key")
    assert first is not None and first.side_effect_count == 1
    assert second is not None and second.side_effect_count == 1
