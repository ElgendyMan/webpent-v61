# Juice Shop Governance Decision — Pre-P10 Run Gate

**Decision ID:** `juice-shop-governance-20260826-01`
**Prepared:** 2026-08-26
**Scope:** Authorized local loopback lab only (`http://127.0.0.1:3000`)
**Target version:** Juice Shop `20.2.0`
**Source commit:** `1618a611b173b4bf114028e6e02549950606e29d`

## Decision status

> **Governance status: `PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF`.**

This packet freezes the current dispositions and the exact hash inputs that a reviewer must inspect. It is not a self-approval, does not authorize official isolated P10 runs, and does not confer P10 or VIP qualification.

The independent reviewer must review the exact packet, the referenced mapping/oracle records, and the source-derived snapshot. The reviewer must explicitly approve or reject the proposed final scoring set and confirm the treatment of the seven non-scoring cases.

## Case dispositions

| Case | Current disposition | Official scoring treatment | Basis |
|---|---|---|---|
| `juice.access_log_disclosure.v1` | Implemented and retested; governance confirmation pending | Excluded from the final set until the predicate is independently confirmed | The target-local implementation produced a verified, sealed, replayable proof, but the currently recorded independent oracle decision accepted only three other predicates. |
| `juice.directory_listing.v1` | `blocked` | Excluded until safely reopened | The local runtime did not satisfy the directory-index causal predicate. |
| `juice.forgotten_backup.v1` | `blocked` | Excluded until safely reopened | Candidate and independent control returned `403`; anonymous read precondition was not demonstrated. |
| `juice.misplaced_signature_file.v1` | `blocked` | Excluded until safely reopened | The mapped resource was absent from the version-matched source checkout and runtime did not establish signature exposure. |
| `juice.privacy_policy_proof.v1` | `out_of_scope` pending governance confirmation | Non-scoring | Policy/challenge-completion behavior is not a vulnerability causal predicate. |
| `juice.public_scoreboard_route.v1` | `out_of_scope` pending governance confirmation | Non-scoring | Route reachability does not establish a security weakness. |
| `juice.security_policy.v1` | `out_of_scope` pending governance confirmation | Non-scoring | A public security-policy document is not a vulnerability oracle. |
| `juice.well_known_security_policy.v1` | `out_of_scope` pending governance confirmation | Non-scoring | The alternate policy location duplicates policy semantics and is not an independent vulnerability. |

Blocked and out-of-scope cases are **not FN** and must not be counted as TP, FP, or recall denominators.

## Proposed final approved set

The only predicates currently accepted by the recorded independent oracle review are:

```text
juice.error_handling.v1
juice.exposed_metrics.v1
juice.local_xss.v1
```

This is a **proposed** set pending independent governance signoff. It contains 3 cases and 3 classes, which is below the project's P10 minimum gate of 10 cases and 6 classes. Therefore, official 3-run P10 execution remains blocked.

## Hash lock

| Input | Exact value |
|---|---|
| Canonical mapping hash | `sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5` |
| Canonical oracle mapping hash | `sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c` |
| Reviewed oracle-contract hash | `sha256:d16e139eebcbe7e88f62058e22aa4ffa31ed96a5af8c5187cc29937304902dee` |
| Oracle decision file hash | `sha256:637b1f7e10e4224d60e3bcf29abdcaadb2e87aa66ed03d776668b94f1454a97c` |
| Ground-truth document hash | `sha256:84bf4111235b546b337fbd3e76207d43a8e7a05f39685dd9ed51f739468aea52` |
| Source snapshot file hash | `sha256:ecb29540165f4f33462d69f213b79cb14e72e8ec0ff2477466d0e3acd12e3381` |
| Source snapshot ID | `gt-snapshot-20260826-02` |

The source snapshot is independent of WebPent run output and records source/catalog consistency only. It is not a vulnerability verdict approval. The live catalog body digest is retained as metadata only and is not substituted for the snapshot-file hash.

## Run gate

```text
official_isolated_p10_runs_authorized = false
p10 = NOT_QUALIFIED
p9 = NOT_QUALIFIED
vip = NOT_QUALIFIED
```

Blocking conditions are: missing independent governance signoff; fewer than 10 approved cases; fewer than 6 approved classes; missing governance confirmation for access-log; and missing full ground-truth result approval.

After the reviewer signs the exact packet, the project may proceed only if the signed decision freezes a complete approved set and every approved case has an accepted semantic causal predicate, safe precondition, baseline/candidate/independent-negative-control evidence, central verification, sealed ProofBundle, `verify_seal()`, and replay evidence. Only then may the required isolated runs begin.

## Safety and scope

All reviewed activity is limited to the authorized local loopback target and safe read-only operations. No external destination, credential use, raw HTTP retention, Generic Core modification, or frozen P10 artifact modification is authorized by this packet.
