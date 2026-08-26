# P10 Gap Matrix v1 — Juice Shop approved cases

**Audit scope:** static repository and frozen P10 governance artifacts only. No Juice Shop container was started and no live target contact or new evidence was produced during this audit.

**Decision vocabulary:**

- **Present / contract:** the repository contains an explicit binding or contract.
- **Partial:** a target-scoped binding or framework exists, but live execution/proof is not demonstrated.
- **Missing:** the current repository does not provide a case-specific causal/proof implementation.
- **Not verified:** the action is designed to be bounded and local, but no live precondition check was performed in this audit.

## Approved cases

| Case ID | Operation / path | Live adapter | Causal oracle | Negative control | Sealing / replay | Safe preconditions | Primary gap |
|---|---|---|---|---|---|---|---|
| `juice.access_log_disclosure.v1` | `navigate` — `/ftp/access.log` | **Partial** — explicit `TargetCaseBinding` and read-only navigation workflow are registered; no live run | **Missing for P10 proof** — current oracle is `http.read_only.log_resource_metadata`, which is metadata-only and not an accepted class-specific causal predicate | **Missing case-specific proof** — central contract exists, but no case-bound negative-control result | **Framework only** — `SemanticProofRunner`/ProofBundle machinery exists, but no sealed bundle or replay result for this case | **Designed safe; not verified live** — relative local GET/navigation, no credentials or state-changing request | Define and independently approve a causal log-disclosure oracle plus negative control, then run and seal it |
| `juice.directory_listing.v1` | `navigate` — `/ftp` | **Partial** — explicit case binding and read-only navigation workflow; no live run | **Missing for P10 proof** — resource existence/metadata does not by itself prove directory-listing vulnerability semantics | **Missing case-specific proof** | **Framework only** — no case bundle, `verify_seal`, or replay result | **Designed safe; not verified live** — bounded local read-only route | Define directory-listing causal predicate and independent negative control; connect it to the runner |
| `juice.error_handling.v1` | `navigate` — `/rest/qwertz` | **Partial** — explicit binding and navigation workflow; semantic profile is target-scoped | **Partial / oracle accepted** — `juice.error_disclosure.v1` is registered as promotable with `verbose_server_error`; reviewer accepted the predicate, but no live causal proof exists | **Contract present, result missing** — profile reason requires negative control, but no run artifact exists | **Framework available, evidence missing** — no sealed/replayed case bundle | **Designed safe; not verified live** — bounded local GET to a non-mutating route | Execute baseline/action/negative control, seal bundle, replay independently, and include in all 3 runs |
| `juice.exposed_metrics.v1` | `navigate` — `/metrics` | **Partial** — explicit binding and navigation workflow; semantic profile is target-scoped | **Partial / oracle accepted** — `juice.exposed_metrics.v1` is promotable with `prometheus_publication`; reviewer accepted the predicate, but no live proof exists | **Contract present, result missing** — profile explicitly requires negative control; no result artifact exists | **Framework available, evidence missing** — no sealed/replayed case bundle | **Designed safe; not verified live** — bounded local read-only metrics request | Execute and seal the accepted oracle with an independent negative control in 3 isolated runs |
| `juice.forgotten_backup.v1` | `navigate` — `/ftp/coupons_2013.md.bak` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — resource existence/metadata is not yet an approved causal oracle for forgotten-backup semantics | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded local read-only route; raw content must not be retained | Create a metadata-safe causal predicate that proves unintended backup exposure without storing raw content |
| `juice.local_xss.v1` | `typed_search` — `/` | **Partial-to-implemented** — explicit MAT search workflow executor exists; no live run | **Partial / oracle accepted** — `dom.safe_search_sink_observation` was accepted for this case, but the current repository has no live ProofBundle proving the causal signal | **Contract required, result missing** — DOM-safe observation can be paired with an independent benign search control, but no sealed result exists | **Framework available, evidence missing** — no replayable bundle or final run matrix entry | **Designed safe; not verified live** — browser search interaction, no credentials; must retain only redacted categorical DOM facts | Run baseline/control/search observations with a bounded DOM oracle, then seal and replay without retaining raw DOM/payload |
| `juice.misplaced_signature_file.v1` | `navigate` — `/ftp/suspicious_errors.yml` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — signature metadata alone is not yet an accepted causal vulnerability predicate | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded local read-only route | Define what exposure is security-relevant, add a negative control, and obtain independent oracle approval |
| `juice.privacy_policy_proof.v1` | `navigate` — long relative path under `/we/...` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — a policy/resource metadata observation does not prove the intended semantics without a causal contract | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded relative local navigation; no external destination | Define a target-backed privacy/miscuration oracle and safe negative control; do not count text presence alone |
| `juice.public_scoreboard_route.v1` | `navigate` — `/score-board` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — public route metadata is currently observation-only and not an approved causal predicate | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded local read-only route | Decide whether public scoreboard exposure is in scope and define a causal oracle that distinguishes intended public functionality from vulnerability |
| `juice.security_policy.v1` | `navigate` — `/security.txt` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — policy resource metadata alone is not a causal vulnerability proof | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded local read-only route | Define the security-relevant condition and an independent negative control; obtain oracle approval |
| `juice.well_known_security_policy.v1` | `navigate` — `/.well-known/security.txt` | **Partial** — explicit binding and read-only navigation workflow; no live run | **Missing for P10 proof** — policy resource metadata is frozen as a mapping contract only | **Missing case-specific proof** | **Framework only** — no sealed/replayed bundle | **Designed safe; not verified live** — bounded local read-only route | Define whether this is a vulnerability or an informational surface, then freeze a causal oracle before metrics |

## Aggregate findings

| Capability | Count | Interpretation |
|---|---:|---|
| Approved cases with explicit case binding | 11 / 11 | Catalog and target binding exist in `JuiceShopTargetAdapter`; this is not evidence of a successful live run |
| Approved cases with a declared workflow ID | 11 / 11 | All map to bounded `navigate` or `typed_search`; navigation execution is generic, while MAT search has an explicit browser executor |
| Cases with reviewer-accepted oracle predicates | 3 / 11 | `error_handling`, `exposed_metrics`, and `local_xss` only |
| Cases with promotable semantic profiles in the adapter | 2 / 11 | `error_handling` and `exposed_metrics`; local XSS uses the DOM-safe oracle contract rather than a semantic HTTP profile |
| Cases with live causal evidence in this audit | 0 / 11 | No target was started and no live evidence was fabricated |
| Cases with sealed/replayed ProofBundles in this audit | 0 / 11 | Central machinery exists, but no case/run artifact was found or produced |
| Cases with complete 3-run traceability | 0 / 11 | Run-case matrix is still pending |
| Cases safe by declared bounded design | 11 / 11 | The approved registry operations are local read-only navigation/search; live preconditions remain unverified |

## Important governance distinction

The adapter and workflow rows above demonstrate **implementation inventory**, not vulnerability confirmation. The frozen ground truth explicitly states that the mapping review approved 11 cases but the oracle review accepted predicates for only 3 cases, and that the remaining 8 are not to be counted as FN until class-specific causal oracles are approved.

The current repository therefore supports a safe bounded execution plan for all 11 cases, but it does **not** yet support a valid full P10 metrics run. The minimum blocker is not the number of routes; it is the absence of independent, case-specific causal contracts and sealed/replayable proof for the eight metadata-only cases.

## Integration blocker before any live run

The adapter currently emits the navigation workflow identifier `juice-shop-read-only-navigation`, while the frozen P10 ground truth records `juice-shop-readonly-navigation` for the ten navigation cases. This is a **fail-closed integration mismatch**, not a reason to alter the frozen ground truth. Before live execution, the adapter/runner contract must reconcile the identifier through a reviewed code change and a compatibility test; otherwise the run cannot be reliably joined to the approved case matrix. The typed-search identifier `juice-shop-mat-search` is consistent.

## Source records reviewed

- `docs/juice_shop_p10_ground_truth_v1.json`
- `src/webpent/benchmark/juice_shop_safe_cases.py`
- `src/webpent/benchmark/juice_shop_target_adapter.py`
- `src/webpent/shared/semantic_observations.py`
- `src/webpent/shared/semantic_proof_runner.py`
- `src/webpent/shared/proof_oracles.py`
- `docs/p10_oracle_semantics_decision_v1.json`

**Audit conclusion:** `P10 = NOT_QUALIFIED`; the next technically valid work is oracle-contract closure for the eight not-scored cases, followed by offline contract tests, bounded local live runs, sealing/replay, and only then the three-run metrics gate.
