from webpent.shared.research_intelligence import GapKind, KnowledgeGapEngine


def test_runtime_feedback_creates_bounded_gaps_from_explicit_failures():
    gaps = KnowledgeGapEngine().derive(
        {
            "runtime_feedback": {
                "browser": [{"status": "browser_crash", "target_url": "https://app.test"}],
                "gmail": [
                    {"status": "delayed_delivery", "target_ref": "mailbox://a"},
                    {"status": "duplicate_email", "target_ref": "mailbox://a"},
                    {"status": "expired_otp", "target_ref": "mailbox://a"},
                ],
                "validator": [
                    {
                        "status": "missing-validator",
                        "target_ref": "https://app.test/object/1",
                        "evidence_refs": ["observation://validator/1"],
                    }
                ],
            }
        }
    )

    assert any(gap.kind == GapKind.WORKFLOW for gap in gaps)
    assert any(gap.kind == GapKind.ORACLE for gap in gaps)
    assert any("browser session recovery" in gap.unknown for gap in gaps)
    assert any("missing-validator" in gap.unknown for gap in gaps)
    assert all(gap.candidate_actions for gap in gaps)


def test_runtime_feedback_ignores_success_and_deduplicates_same_failure():
    feedback = {
        "runtime_feedback": {
            "browser": [
                {"status": "completed", "target_url": "https://app.test"},
                {"status": "browser_crash", "target_url": "https://app.test"},
                {"status": "browser_crash", "target_url": "https://app.test"},
            ],
            "validator": [{"status": "unknown", "target_ref": "https://app.test"}],
        }
    }
    gaps = KnowledgeGapEngine().derive(feedback)

    assert len(gaps) == 1
    assert gaps[0].kind == GapKind.WORKFLOW
    assert "completed" not in gaps[0].unknown
    assert "unknown" not in gaps[0].unknown
