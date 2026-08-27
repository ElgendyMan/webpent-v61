# Option B — Local Causal Lab v1

**Author:** Manus AI — non-human attributable technical review

**Campaign:** `option-b-local-causal-lab-v1-20260827`

**Status:** Completed safe precondition pass; all six approved-track cases are **BLOCKED before network execution**.

**Authorization:** Imported owner directive for the current bounded task only. The imported record does not claim owner identity, human signature, independent governance signoff, or qualification approval.

## Executive determination

The approved Option B boundary was implemented as target-local, fail-closed infrastructure. The runner pinned the imported authorization reference, checked the declared source revisions and source-file hashes, modeled only opaque synthetic identities and disposable canaries in memory, and evaluated runnable preconditions before any case request. No login, credential, token, cookie, reset endpoint, application mutation, redirect, external destination, OAST callback, or raw response persistence was used.

All six selected tracks remain **BLOCKED**, not confirmed, clean, TP, FP, or FN. WebGoat IDOR requires a prior POST-created `LessonSession`, which is outside the approved GET-only/no-login boundary [1] [2]. WebGoat path traversal has a GET route, but the source-backed handler rejects raw traversal markers and no safe target-local disposable canary injection route was available without broad filesystem risk [3] [4]. crAPI cases require authenticated ownership/session context or a stateful report/object fixture, and the local crAPI runtime image `RepoDigest` could not be collected; therefore no crAPI causal evidence is admitted [5] [6] [7] [8].

> **No target-backed baseline, candidate, or independent-control observation was collected. Consequently, no causal oracle was evaluated and no ProofBundle was sealed, verified, or replayed.**

## Scope and authorization boundary

| Control | Applied value | Result |
|---|---|---|
| Targets | WebGoat IDOR/path traversal; crAPI object-access | Approved tracks only |
| Network | `127.0.0.1` loopback and declared origin only | Enforced by contract; no case socket operation occurred |
| Methods | `GET` only | Enforced; non-GET rejected in regression tests |
| Redirects/DNS/external callbacks | Forbidden | Rejected by contract; not attempted |
| Credentials/login/session bootstrap | Forbidden | IDOR and crAPI auth cases blocked |
| Application mutation/reset endpoint | Forbidden | Not invoked |
| Raw bodies/headers/cookies/tokens/personal data | No persistence | Redacted-only model tested |
| Official P10 / Bug Bounty | Closed | Unchanged |

The controlling authorization import is [`LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json`](../owner_decision/LOCAL-CAUSAL-LAB-OPTION-B-OWNER-APPROVAL-IMPORT-v1.json). Its source text SHA-256 is `2784b4746e96419a3dadea2e765d58a9dbc719b283bb683b38bbe95c5850230b`; the original decision packet remains `PENDING_OWNER_APPROVAL` and was not modified.

## Target provenance

| Target | Source revision | Source verification | Runtime status | Evidence consequence |
|---|---|---|---|---|
| OWASP WebGoat | `7517acca95d9851da706452454c223dd13545ef4` | Declared source files matched their expected hashes | Java version collected; immutable build/runtime digest unavailable | No causal evidence admitted |
| crAPI | `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | Declared controller/route files matched their expected hashes | `runtime_digest_unavailable`; Docker `RepoDigest` unavailable | All crAPI cases blocked |

The machine-readable artifact records every expected and observed source-file hash. It intentionally records no environment variables, process arguments, credentials, tokens, response bodies, or headers.

## Case decisions

| Case ID | Source-backed reason | Precondition result | Final classification |
|---|---|---|---|
| `webgoat.idor.view_other_profile.v1` | GET profile route depends on prior lesson session established by POST login | Required session/credentials not approved; runtime build digest also unavailable | **BLOCKED** |
| `webgoat.path_traversal.v1` | GET route exists, but handler rejects unsafe raw markers and target-local canary injection is not safely available | No bounded canary route/fixture; runtime build digest unavailable | **BLOCKED** |
| `crapi.profile_video_object_access.v1` | Source candidate appears owner-scoped; authenticated ownership fixture unavailable | Login/token/session and runtime digest blockers | **BLOCKED** |
| `crapi.vehicle_location_bola.v1` | Direct UUID lookup is a source-backed BOLA candidate only | Authenticated synthetic owner/requester pair and runtime digest unavailable | **BLOCKED** |
| `crapi.community_post_object_access.v1` | GET route is behind authentication middleware; post fixture creation is stateful | Auth/session and mutation/fixture blockers; runtime digest unavailable | **BLOCKED** |
| `crapi.mechanic_report_object_access.v1` | Retrieval requires a pre-existing report; report creation is stateful | Auth/session and creation/reset blockers; runtime digest unavailable | **BLOCKED** |

These decisions are represented in the JSON artifact with a Failure Record, RCA, target-local classification, safety determination, improvement proposal, regression status, and same-condition before/after comparison for every case.

## Fixture and reset evidence

A separate in-memory regression fixture was implemented under `src/webpent/adapters/local_causal_lab/fixtures.py`. It uses only opaque identifiers such as `test_subject_a` and semantic canary labels. It does not create application state and does not represent target evidence. Tests verify that the fixture rejects credential/session material, raw canary persistence, application mutation, and application reset endpoint calls. Its state hash remains stable in the safe regression path, and the runner records `verified_no_mutation` with `network_attempted=false` for all case records.

## Causal evaluation and proof status

The central causal cycle was **not entered** for any case because the precondition gate stopped execution. Therefore the result is not a weak confirmation and not an observation-only vulnerability result. It is a safe, auditable blocker result:

| Evidence component | Result |
|---|---|
| Baseline GET | Not run |
| Candidate GET | Not run |
| Independent negative control | Not run |
| Causal oracle | Not evaluated |
| ProofBundle | Not created |
| `verify_seal()` | Not run |
| Isolated replay | Not run |
| Cleanup | Verified no mutation; no reset endpoint and no network case request |

## Validation performed

The focused regression suite passed **25 tests**, covering the approval import, original pending decision packet, loopback and same-origin policy, GET-only enforcement, route/query allowlists, redirect rejection, traversal-marker rejection, raw-response redaction, auth-ready misuse, independent-control requirement, opaque fixture identities, state-hash/reset checks, and runner blocker output.

The local runner generated [`OPTION-B-LOCAL-CAUSAL-LAB-RESULT-v1.json`](./OPTION-B-LOCAL-CAUSAL-LAB-RESULT-v1.json), reporting six approved-track records, six blocked cases, zero target-backed causal confirmations, and zero sealed ProofBundles.

## Improvement cycle and remaining authorization gaps

The implemented improvement is target-local contract and precondition enforcement, not an auth bypass or generic-core change. The same-condition comparison is intentionally unchanged: every case is blocked before and after because the required safe prerequisite remains unavailable. The next executable step would require a **new, explicit owner decision packet** authorizing a non-credential synthetic session/fixture injection mechanism that is source-backed, target-local, disposable, independently resettable, and safe under GET-only candidate execution. Without that separate authorization and immutable runtime/build digests, the cases must remain blocked.

No frozen ground truth, scoring thresholds, generic core, official run gate, or qualification state was changed. The project remains:

| State | Value |
|---|---|
| `human_independent_signoff_obtained` | `false` |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |

## References

[1]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java "WebGoat IDOR profile source"

[2]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java "WebGoat IDOR login source"

[3]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java "WebGoat path traversal retrieval source"

[4]: file:///tmp/webgoat-source/src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java "WebGoat path traversal source"

[5]: file:///tmp/crapi-source/services/identity/src/main/java/com/crapi/controller/VehicleController.java "crAPI vehicle controller source"

[6]: file:///tmp/crapi-source/services/identity/src/main/java/com/crapi/controller/ProfileController.java "crAPI profile controller source"

[7]: file:///tmp/crapi-source/services/community/api/router/routes.go "crAPI community routes source"

[8]: file:///tmp/crapi-source/services/workshop/crapi/mechanic/urls.py "crAPI mechanic routes source"
