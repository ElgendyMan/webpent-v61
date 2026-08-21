from webpent.agents.smart_campaigns.agent import (
    _information_task_from_record,
    _record_information_evidence,
)
from webpent.shared.research_intelligence import ActionClass, ResearchSession


def _state() -> dict:
    return {
        "engagement_id": "engagement:evidence-tests",
        "client_id": "client:evidence-tests",
        "target": {"url": "https://target.test"},
        "smart_governance": {"profile": "safe-smart"},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
    }


def _task(record: dict):
    task = _information_task_from_record(record, state=_state(), index=0)
    assert task is not None
    return task


def _session() -> ResearchSession:
    return ResearchSession(
        session_id="session:evidence-tests",
        engagement_id="engagement:evidence-tests",
        client_id="client:evidence-tests",
    )


def test_research_observation_is_positive_only_with_sealed_proof() -> None:
    record = {
        "action_id": "research:positive",
        "action_class": "discovery",
        "target_ref": "https://target.test/health",
        "method": "GET",
        "fingerprint": "fp-positive",
        "hypothesis_id": "hypothesis:positive",
        "proof_evidence": [{"status_code": 200}],
    }
    session = _session()
    result = _record_information_evidence(
        session,
        _task(record),
        record,
        {"status": "executed", "output_available": True, "proof_bundle_sealed": True},
    )
    assert result == "positive"
    assert len(session.positive_evidence_ledger) == 1
    assert session.negative_evidence_ledger == []


def test_negative_control_requires_explicit_control_signal() -> None:
    record = {
        "action_id": "research:negative-control",
        "action_class": ActionClass.NEGATIVE_CONTROL.value,
        "target_ref": "https://target.test/health",
        "method": "GET",
        "fingerprint": "fp-negative",
        "hypothesis_id": "hypothesis:negative",
        "negative_control_payload": "neutral-control",
    }
    session = _session()
    task = _task(record)
    assert (
        _record_information_evidence(
            session,
            task,
            record,
            {"status": "executed", "output_available": True},
        )
        == "inconclusive"
    )
    assert session.negative_evidence_ledger == []
    assert (
        _record_information_evidence(
            session,
            task,
            record,
            {
                "status": "executed",
                "output_available": True,
                "negative_control_present": True,
            },
        )
        == "negative"
    )
    assert len(session.negative_evidence_ledger) == 1


def test_information_output_without_proof_is_inconclusive() -> None:
    record = {
        "action_id": "research:observed",
        "action_class": "discovery",
        "target_ref": "https://target.test/health",
        "method": "GET",
        "fingerprint": "fp-observed",
        "hypothesis_id": "hypothesis:observed",
    }
    session = _session()
    assert (
        _record_information_evidence(
            session,
            _task(record),
            record,
            {"status": "executed", "output_available": True},
        )
        == "inconclusive"
    )
    assert session.positive_evidence_ledger == []
    assert session.negative_evidence_ledger == []
