from dataclasses import replace

from webpent.irta.v3 import ProofBundle


def _bundle() -> ProofBundle:
    return ProofBundle(
        target_id="target-alpha",
        case_id="case-1",
        baseline_digest="b" * 64,
        candidate_digest="c" * 64,
        control_digest="d" * 64,
        causal_signal="owner-delta",
        replay_token="replay-1",
    ).sealed()


def test_complete_bundle_is_sealed_replayable_and_eligible() -> None:
    bundle = _bundle()
    assert bundle.verify_seal()
    assert bundle.replay("replay-1")
    assert bundle.scoring_eligible()


def test_tampering_invalidates_seal_and_scoring() -> None:
    bundle = replace(_bundle(), candidate_digest="tampered")
    assert not bundle.verify_seal()
    assert not bundle.replay("replay-1")
    assert not bundle.scoring_eligible()


def test_missing_causal_signal_is_not_eligible() -> None:
    bundle = replace(_bundle(), causal_signal="").sealed()
    assert bundle.verify_seal()
    assert not bundle.scoring_eligible()
