# MOCK-FN-001 — Before/After Comparison

## Status

`comparison_status = pending_independent_review_and_implementation`

The Improvement Proposal has not been approved by an independent reviewer. Therefore the proposed ready-state implementation was not started, no improvement commit exists, and no post-change run may be reported.

## Comparison matrix

| Dimension | Before: default fixture | After: required post-approval run |
|---|---|---|
| fixture state | default, precondition not ready | opt-in ready-state fixture, if approved and implemented |
| runner result | `blocked` | not yet measured |
| observation path | not reached | must produce redacted metadata-only observations |
| candidate/control separation | not reached | must be independently separated |
| causal signal | absent by design | must be produced only through the central verifier |
| ProofBundle | absent by design | must be sealed and replayed |
| network/state mutation | none | must remain none |
| Generic Core changes | none | must remain none |
| regression status | default-blocked regression passes | not applicable until implementation |

## Acceptance decision

`accepted = false`

`reason = independent_proposal_approval_missing`

This file is a gate record, not evidence of an improvement. The cycle may be closed only after an independent reviewer approves the proposal, a dedicated implementation commit is created in the Mock adapter scope, regression tests pass, the same baseline conditions are rerun, and the before/after evidence is sealed and independently replayed.
