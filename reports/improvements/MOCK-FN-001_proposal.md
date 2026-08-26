# Improvement Proposal — MOCK-FN-001

## Scope

This proposal addresses the deterministic Mock Target fixture's inability to exercise a successful, redacted lifecycle path. It does not change the Generic Core, Juice Shop, WebGoat, crAPI, or any external target.

## Problem

The default Mock Target intentionally reports `preconditions_ready = false`. That behavior is valuable for blocked-classification regression, but it leaves no opt-in ready fixture for testing the positive lifecycle path.

## Proposed change

Add a test-only ready-state Mock adapter factory in `adapters/mock_target`. The factory will:

1. keep the existing default adapter unchanged and blocked;
2. expose only loopback, read-only navigation;
3. produce metadata-only observations with no raw body, headers, cookies, credentials, or payloads;
4. use separate candidate and negative-control observation branches;
5. call the existing central verifier for any confirmation;
6. retain sealed/replayable ProofBundle requirements;
7. return `blocked`, `unsupported`, or `inconclusive` rather than inventing evidence when a fixture input is absent.

## Architecture decision

The change belongs in the Mock Target fixture, not in `shared/` and not in the GenericWebAdapter. No target-specific route or selector is added to Generic Core. The factory is deterministic and has no network dependency.

## Safety impact

Expected impact is non-increasing. The default blocked adapter remains unchanged. The ready fixture performs no external I/O and cannot accept mutating operations. It stores redacted categorical facts only.

## Acceptance criteria

| Criterion | Test |
|---|---|
| Default blocked behavior remains unchanged | Existing Mock blocked test |
| Ready fixture reaches observation path | New deterministic lifecycle test |
| Candidate/control remain distinct | Negative-control separation assertion |
| No automatic confirmation | Runner result without verifier stays non-confirmed |
| Confirmation requires central verifier | ProofBundle seal/replay test |
| No target leakage | Generic neutrality guard and adapter-scope review |
| No serialization of runtime objects | Contract serialization test |
| Full suite remains green | Ruff, compileall, pytest, G-02, secrets, diff checks |

## Rollback

Revert the dedicated improvement commit. The original default Mock adapter and its blocked regression test remain valid independently.

## Review status

`proposal_status = pending_independent_review`

`implementation_allowed = false until reviewer approval is recorded`
