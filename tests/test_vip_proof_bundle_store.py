from __future__ import annotations

import pytest

from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.campaign_executor import CampaignTask
from webpent.shared.proof_bundle_store import ProofBundleStore, ProofBundleStoreError
from webpent.shared.runtime import RuntimeFactory


def _sealed_bundle(*, engagement_id: str = "eng-1", finding_id: str = "finding-1"):
    return build_proof_bundle(
        engagement_id=engagement_id,
        finding_id=finding_id,
        hypothesis_id="hyp-1",
        target_fingerprint="target-sha256",
        scope_context={"origin": "https://example.test"},
        identity_context={"role": "owner"},
        evidence=(
            {"status": 200, "body_sha256": "sha256:positive"},
        ),
        evidence_refs=("replay://finding-1/positive",),
        negative_control={"status": 404, "body_sha256": "sha256:negative"},
        baseline={"status": 404},
        request_evidence=({"method": "GET", "path": "/object/1"},),
        response_evidence=({"status": 200, "body": "redacted"},),
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id="test-validator",
        validator_version="1.0.0",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal(actor="test")


def test_store_rejects_unsealed_and_accepts_sealed_bundle() -> None:
    store = ProofBundleStore()
    unsealed = _sealed_bundle().model_copy(update={"sealed": False, "seal_digest": None})

    with pytest.raises(ProofBundleStoreError, match="sealed"):
        store.put(unsealed)

    bundle = _sealed_bundle()
    assert store.put(bundle) == bundle.bundle_id
    assert store.get(bundle.bundle_id, engagement_id=bundle.engagement_id) == bundle


def test_store_is_idempotent_but_rejects_bundle_id_conflict() -> None:
    store = ProofBundleStore()
    bundle = _sealed_bundle()
    assert store.put(bundle) == bundle.bundle_id
    assert store.put(bundle.model_dump(mode="json")) == bundle.bundle_id

    conflicting = _sealed_bundle(finding_id="finding-2").model_copy(
        update={"bundle_id": bundle.bundle_id, "sealed": False, "seal_digest": None}
    ).seal(actor="test")
    with pytest.raises(ProofBundleStoreError, match="conflict"):
        store.put(conflicting)


def test_store_isolates_engagements_and_returns_safe_snapshot() -> None:
    store = ProofBundleStore()
    first = _sealed_bundle(engagement_id="eng-1", finding_id="finding-1")
    second = _sealed_bundle(engagement_id="eng-2", finding_id="finding-2")
    store.put(first)
    store.put(second)

    assert store.get(first.bundle_id, engagement_id="eng-2") is None
    assert [item.bundle_id for item in store.list(engagement_id="eng-1")] == [first.bundle_id]
    snapshot = store.snapshot(engagement_id="eng-2")
    assert len(snapshot) == 1
    assert snapshot[0]["engagement_id"] == "eng-2"
    assert isinstance(snapshot[0]["chain_of_custody"], list)


def test_runtime_factory_injects_append_only_store_by_default() -> None:
    context = RuntimeFactory.create(
        engagement_id="eng-runtime",
        campaign_id="campaign-runtime",
        target_origin="https://example.test",
        manifest={"schema_version": "test", "capabilities": []},
        use_default_ledger=False,
    )

    assert isinstance(context.proof_bundle_store, ProofBundleStore)
    assert context.valid is True



def _campaign_task() -> CampaignTask:
    return CampaignTask(
        task_id="task-proof-store",
        engagement_id="eng-1",
        asset_id="asset-1",
        source_evidence_ids=("surface-1",),
        vulnerability_class="idor",
        hypothesis_id="hyp-1",
        target_url="https://example.test/object/1",
    )


def test_action_executor_persists_bundle_before_exposing_it() -> None:
    from webpent.shared.campaign_executor import ActionExecutor, CampaignTaskStatus

    store = ProofBundleStore()
    executor = ActionExecutor(None, proof_bundle_store=store)
    record = executor._record(
        _campaign_task(),
        CampaignTaskStatus.EXECUTED,
        "executed",
        output={
            "finding_id": "finding-store",
            "proof_evidence": [{"status": 200, "body": "redacted"}],
            "evidence_refs": ["replay://finding-store/positive"],
            "negative_control": {"status": 404},
        },
    )

    assert record["proof_bundle_store_status"] == "stored"
    assert record["proof_bundle_sealed"] is True
    assert len(store) == 1


class _FailingStore:
    def put(self, _value: object) -> str:
        raise RuntimeError("store unavailable")


def test_action_executor_fails_closed_when_bundle_store_fails() -> None:
    from webpent.shared.campaign_executor import ActionExecutor, CampaignTaskStatus

    executor = ActionExecutor(None, proof_bundle_store=_FailingStore())
    record = executor._record(
        _campaign_task(),
        CampaignTaskStatus.EXECUTED,
        "executed",
        output={
            "finding_id": "finding-store-failure",
            "proof_evidence": [{"status": 200}],
            "evidence_refs": ["replay://finding-store-failure/positive"],
            "negative_control": {"status": 404},
        },
    )

    assert record["proof_bundle_store_status"] == "failed"
    assert record["proof_bundle"] is None
    assert record["proof_bundle_sealed"] is False
    assert record["proof_bundle_store_error"] == "RuntimeError"
