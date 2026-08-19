# src/webpent/state/state.py
"""webpent.state.state

LangGraph state schema for the WebPent Framework V3.

V3 extends V2's state with ``auth_state`` (Phase 1) and
``optimization_retries`` (Phase 2 — Payload Optimizer loop).

V5 Sprint 6: Adds ``stealth_mode`` flag propagated from the CLI
``--stealth`` option. Tool wrappers and the Playwright sandbox read
this flag to insert jitter and rate-limit delays.

V5 Sprint 11: Adds ``executive_summary`` and ``risk_score`` fields
populated by the new ``executive_summary_node`` before the reporter
finalizes the report.

V6 Absolute-Flawless P0 FIX (CISO audit — LangGraph State Mutation):
    ``crawled_data``, ``session_cookies``, and ``credentials`` were
    previously declared as bare ``dict[...]`` fields without
    ``Annotated[..., reducer]`` annotations. LangGraph treats
    un-annotated dict fields as last-write-wins, which means parallel
    branches writing to the same field silently overwrite each other.
    Worse, nodes that needed to update a single entry (e.g. one new
    session cookie) had to read the whole dict, mutate it in place,
    and write it back — and the in-place mutation was invisible to
    LangGraph's snapshot/checkpoint logic, so resuming a paused
    engagement could lose the update.

    All three fields now carry the ``merge_dicts`` reducer, which
    deep-merges new values into the existing dict instead of
    overwriting. This makes parallel-branch writes safe AND makes
    per-key updates visible to the checkpoint layer. Downstream
    nodes (e.g. ``pentest_worker._mark_pending_as_human_review``)
    now return ``{"findings": [updated_list]}`` dicts instead of
    mutating ``state["findings"]`` in place — see the matching fix
    in ``pentest_worker.py``.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from webpent.models.findings import Finding
from webpent.models.hypothesis import Hypothesis
from webpent.models.targets import Target
from webpent.state.reducers import (
    merge_auth_state,
    merge_dicts,
    merge_findings,
    merge_hypotheses,
    merge_lists,
    merge_payloads,
    merge_retries,
)


class PentestState(TypedDict, total=False):
    """Central LangGraph state shared across all V3.5 pentest agents.

    V7 Cognitive Upgrade (Phase 1 — Hypothesis Engine):
        ``hypotheses`` was previously ``list[str]`` — a flat list of
        free-form text with no provenance, status, or confidence. It
        is now ``list[Hypothesis]``, where each entry is a first-class
        Pydantic model with stable UUID, lifecycle status, numeric
        confidence score, evidence refs, origin tracking, and an
        optional parent-hypothesis reference for Rabbit Hole branches
        (Phase 7). The reducer stays ``merge_lists`` (append-only) —
        only the element type changed. This is a breaking type change
        done as a single atomic migration per Section 3 of the plan:
        there is no window where the field holds a mixed-type list.
    """

    target: Target
    messages: Annotated[list[BaseMessage], add_messages]
    findings: Annotated[list[Finding], merge_findings]
    current_phase: str
    # V9 P0 B2: hypotheses now uses merge_hypotheses (upsert-by-id) instead
    # of merge_lists (append-only). This prevents duplicates when the
    # strategist returns model_copy(update={"status": ...}) on promote/abandon.
    hypotheses: Annotated[list[Hypothesis], merge_hypotheses]
    lessons: Annotated[list[str], merge_lists]
    payloads_to_test: Annotated[dict[str, list[str]], merge_payloads]
    # V6 Absolute-Flawless: crawled_data now uses merge_dicts so parallel
    # crawler branches (e.g. one per HTTP method) don't clobber each
    # other's results, and per-key updates are visible to checkpoints.
    crawled_data: Annotated[dict[str, Any], merge_dicts]
    # V9 P0-B-2 FIX: auth_state now uses merge_auth_state instead of
    # plain merge_dicts. See merge_auth_state's docstring — plain
    # merge_dicts concatenates auth_state["cookies"] (a list) instead
    # of upserting by cookie name, which corrupts the cookie jar the
    # first time a second write happens (e.g. the validator's mid-scan
    # reauth fix).
    auth_state: Annotated[dict[str, Any], merge_auth_state]
    optimization_retries: Annotated[dict[str, int], merge_retries]

    # V3.5 Phase 3 additions
    errors: Annotated[list[str], merge_lists]
    # V6 Absolute-Flawless: session_cookies now uses merge_dicts so the
    # auth agent can append cookies without overwriting cookies set by
    # the crawler, and per-cookie updates survive checkpoint/resume.
    session_cookies: Annotated[dict[str, str], merge_dicts]

    # V11 BAC/IDOR evidence-first multi-identity context.  These fields are
    # additive and optional so old checkpoints remain loadable.  Identity
    # profiles may contain runtime cookies for the active process, but every
    # report-facing observation is redacted by bac_identity_tester.
    identity_profiles: Annotated[dict[str, Any], merge_dicts]
    bac_observations: Annotated[list[dict[str, Any]], merge_lists]
    bac_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    relational_evidence: Annotated[list[dict[str, Any]], merge_lists]
    # V55 Phase 9: bounded multi-identity authorization matrix. It is a
    # report-safe projection and remains empty unless explicitly enabled.
    authorization_matrix: Annotated[dict[str, Any], merge_dicts]
    subdomain_takeover_observations: Annotated[list[dict[str, Any]], merge_lists]
    subdomain_takeover_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    cloud_storage_observations: Annotated[list[dict[str, Any]], merge_lists]
    cloud_storage_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    jwt_deep_observations: Annotated[list[dict[str, Any]], merge_lists]
    jwt_deep_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    # Operator-supplied, bounded offline candidates only. Never export values.
    jwt_weak_secret_candidates: list[str]
    jwt_public_key_available: bool
    disclosed_report_advisories: Annotated[list[dict[str, Any]], merge_lists]
    advisory_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    # Optional operator-supplied local corpus; never fetched automatically.
    disclosed_report_corpus: list[Any]

    # V4.5 Sprint 2 additions
    # V6 Absolute-Flawless: credentials now uses merge_dicts so multi-step
    # auth flows (e.g. first set username, then set session-token after
    # login) don't lose the username when the second step writes a
    # different key.
    credentials: Annotated[dict[str, str], merge_dicts]
    # Opaque worker-vault references only; never store secret values here.
    secret_refs: Annotated[dict[str, str], merge_dicts]
    playwright_enabled: bool  # Pre-flight health check result

    # V5 Sprint 6 addition
    stealth_mode: bool  # When True, insert jitter + rate-limit delays

    # P0 execution-policy persistence: keep the operator's approval mode in
    # the checkpoint so a resumed engagement cannot silently downgrade from
    # auto-approved execution to an HITL interrupt. Optional for legacy
    # checkpoints; missing values are treated as False by resume code.
    auto_approve: bool

    # V5 Sprint 11 additions
    executive_summary: str  # C-Suite summary generated by executive_summary_node
    risk_score: str  # Overall risk: "Critical" | "High" | "Medium" | "Low"

    # V6.1 addition: phase skipping
    skip_recon: bool  # When True, bypass recon + crawler, go straight to hypothesis

    # Smart Hunter governance is additive and persisted so conditional graph
    # routes remain stable across node transitions and checkpoint resume.
    scan_mode: str
    smart_governance: Annotated[dict[str, Any], merge_dicts]
    # Explicit opt-in for the bounded controller-owned Smart Hunter loop.
    # Legacy and ordinary safe-smart scans remain on the existing adapter path.
    enable_autonomous_controller: bool
    capability_manifest: Annotated[dict[str, Any], merge_dicts]
    action_budget: Annotated[dict[str, Any], merge_dicts]

    # V7 Cognitive Upgrade — Phase 2: Mental Model / Knowledge Graph.
    #
    # Engagement-scoped structured picture of the target — typed nodes
    # (host / endpoint / credential / artifact / service / technology)
    # and typed edges (contains / authenticates_to / discovered_via /
    # references / same_host_as). Populated additively by every
    # discovery node (recon, crawler, hypothesis_analyzer, the four
    # V7 Sprint-2 deep-probers, post_exploit) via the deterministic
    # extractor in webpent.models.mental_model.extract_mental_model_updates.
    #
    # Reducer: merge_dicts (deep-merges node dicts, concatenates edge
    # lists) — same discipline as crawled_data/session_cookies/
    # credentials per the V6 Absolute-Flawless CISO audit fix. Parallel
    # branches can't clobber each other's discoveries; per-key updates
    # are visible to checkpoints.
    #
    # NOT persisted to ChromaDB (engagement-scoped, not cross-
    # engagement). Checkpoint-survives via the existing SqliteSaver
    # that already handles crawled_data. Will contain sensitive
    # material (credential fingerprints — never raw credentials,
    # internal IPs, artifact URLs) by design; treat its persistence
    # with the same care as evidence_bundle/evidence_hash (Phase 6 /
    # Section 6 risk note).
    mental_model: Annotated[dict[str, Any], merge_dicts]

    # V55 canonical evidence boundary. These fields are additive and
    # optional: old checkpoints and legacy node outputs remain valid. The
    # adapter layer stores only normalized, redacted model dumps and uses
    # append-only reducers so parallel tool branches cannot overwrite one
    # another. Raw commands and raw outputs stay outside state and are
    # represented by fingerprints / EvidenceRef records.
    canonical_executions: Annotated[list[dict[str, Any]], merge_lists]
    canonical_observations: Annotated[list[dict[str, Any]], merge_lists]

    # V55 Target Understanding projection. Optional and additive so legacy
    # checkpoints and graph consumers continue to work unchanged.
    target_understanding: Annotated[dict[str, Any], merge_dicts]
    # Application intent is a bounded, report-safe projection used by
    # business-logic and hypothesis agents. Optional for legacy checkpoints.
    application_intent: Annotated[dict[str, Any], merge_dicts]
    policy_assumptions: Annotated[list[str], merge_lists]
    # Cross-engagement pattern hints are advisory, redacted, and append-only.
    pattern_hints: Annotated[list[dict[str, Any]], merge_lists]
    # Human feedback calibration is report-safe and never an execution gate.
    trust_matrix: Annotated[dict[str, Any], merge_dicts]

    # V55 additive Attack Graph projection. The graph is derived from the
    # Mental Model and relational evidence; it is optional and remains absent
    # from legacy runs unless explicitly enabled.
    attack_graph: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 11 report-quality projection. It contains only contract
    # statuses and missing field names, never raw evidence or credentials.
    report_quality_gate: Annotated[dict[str, Any], merge_dicts]

    # V55 workflow understanding projection.  Passive observations and
    # explicit coverage gaps are additive; hypotheses continue through the
    # existing merge_hypotheses reducer and are never auto-promoted.
    workflow_observations: Annotated[list[dict[str, Any]], merge_lists]
    workflow_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]

    # V7 Cognitive Upgrade — Phase 4: Working Memory formalization.
    #
    # The remaining V7 state fields are declared here with proper
    # LangGraph reducers (following the exact merge_dicts / merge_lists
    # discipline already used for crawled_data / session_cookies /
    # credentials / mental_model per the V6 Absolute-Flawless CISO
    # audit fix). They are populated by Phase 5 (Self-Critique),
    # Phase 6 (Decision Log, Goal Tree, Rabbit Hole ledger), and
    # Phase 7 (Rabbit Hole branch goals) — declaring them now (with
    # empty defaults) means Phase 5/6/7 can populate them without
    # further state-schema changes, and the reducers are in place
    # from day one so parallel-branch writes are safe.
    #
    # goal_tree: dict-shaped (one root per engagement, child nodes
    #   per active investigation thread). Phase 6 populates this;
    #   Phase 3's Dynamic Prioritization will select from the tree's
    #   open leaves rather than from a flat list, giving "abandon
    #   this branch" (Phase 5) somewhere concrete to point at.
    #
    # decision_log: append-only list of DecisionLogEntry dicts.
    #   Phase 6 persists each entry to a new SQLite table following
    #   the same CREATE TABLE IF NOT EXISTS + manager-class pattern
    #   already used for findings and hypotheses.
    #
    # rabbit_hole_ledger: dict-shaped visited-assets dedup set
    #   powering Loop Prevention (Phase 6). Keyed by normalised
    #   identity (canonical URL / content hash / credential
    #   fingerprint); value is the discovery_source that first
    #   visited the asset. Phase 7's Rabbit Hole checks this before
    #   any branch action — already-visited -> stop, log it, done
    #   (direct generalization of exploit_chainer's
    #   _already_proposed_pairs).
    goal_tree: Annotated[dict[str, Any], merge_dicts]
    decision_log: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter G5: report-safe, append-only action-selection trace.  It is
    # additive so legacy checkpoints remain loadable and never grants authority.
    decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    # Typed action lifecycle audit; report-safe and append-only.
    lifecycle_events: Annotated[list[dict[str, Any]], merge_lists]
    rabbit_hole_ledger: Annotated[dict[str, Any], merge_dicts]
    # P1 coverage accounting: every strategist candidate gets an explicit
    # disposition; this is advisory metadata and never authorizes execution.
    coverage_ledger: Annotated[dict[str, Any], merge_dicts]
    # Declarative application-aware campaign coverage.  It is report-safe and
    # never authorizes execution or promotes findings.
    campaign_ledger: Annotated[dict[str, Any], merge_dicts]
    # Bounded campaign contracts and hypothesis DAG; advisory only and never
    # an authorization or finding-confirmation channel.
    campaign_plan: Annotated[dict[str, Any], merge_dicts]
    # Redaction-safe causal records; entries are advisory and never findings.
    evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter positive/negative evidence ledgers are report-safe and
    # append-only; they never authorize actions or promote findings.
    positive_evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    negative_evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    # Proof Engine outputs are proposals and telemetry, never execution authority.
    proof_gap_assessments: Annotated[list[dict[str, Any]], merge_lists]
    proof_plan: Annotated[dict[str, Any], merge_dicts]
    proof_observability: Annotated[dict[str, Any], merge_dicts]
    proof_outcomes: Annotated[list[dict[str, Any]], merge_lists]
    # G7 additive artifact channel; bundles are immutable once sealed.
    proof_bundles: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter task-level runtime outcomes. These records are advisory and
    # never promote a campaign or finding without the proof engine.
    campaign_task_outcomes: Annotated[list[dict[str, Any]], merge_lists]
    smart_next_actions: Annotated[list[dict[str, Any]], merge_lists]
    smart_replanning: Annotated[dict[str, Any], merge_dicts]
    # Smart Hunter research-intelligence projections. These fields are
    # report-safe planning telemetry only; they never confirm findings or
    # authorize execution. Legacy checkpoints may omit them safely.
    knowledge_gaps: Annotated[list[dict[str, Any]], merge_lists]
    research_session: Annotated[dict[str, Any], merge_dicts]
    research_decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    smart_information_actions: Annotated[list[dict[str, Any]], merge_lists]
    # Typed research contracts are additive planning telemetry only. They never
    # authorize execution, promote hypotheses, or replace proof validation.
    research_context: Annotated[dict[str, Any], merge_dicts]
    research_candidate_actions: Annotated[list[dict[str, Any]], merge_lists]
    research_unified_decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    # Read-only HTTP observations from the bounded Smart Hunter executor.
    # Bodies, cookies, and raw headers are intentionally excluded.
    smart_http_observations: Annotated[list[dict[str, Any]], merge_lists]

    # V55 Phase 6 adaptive hunt fields.
    # These remain additive and empty on
    # legacy runs. Tasks are scheduler records only; executors continue to
    # enforce scope, evidence, and HITL gates.
    adaptive_revisit_tasks: Annotated[dict[str, Any], merge_dicts]
    adaptive_revisit_ledger: Annotated[dict[str, Any], merge_dicts]
    adaptive_hunt: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 7 advisory planner decisions. These records are optional and
    # empty on legacy runs; they never control graph routing or execute tools.
    planner_decision: Annotated[dict[str, Any], merge_dicts]
    planner_gate_audits: Annotated[list[dict[str, Any]], merge_lists]

    # P2 execution safety projection.  Records why live PoC execution was
    # allowed, paused for HITL, or rejected; never stores payloads/secrets.
    execution_gate: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 10 static JavaScript intelligence. The projection stores
    # hashes, redacted metadata, and bounded mapping tasks only; source text
    # and raw secret values never enter checkpoint state.
    javascript_intelligence: Annotated[dict[str, Any], merge_dicts]
    js_targeted_tasks: Annotated[list[dict[str, Any]], merge_lists]

    # V55+ passive broad-surface coverage. Observations are report-safe,
    # bounded, and never equivalent to confirmed findings.
    surface_security: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 12 memory boundary. The projection stores safe counters,
    # provenance metadata, and feedback audits; it never replaces findings or
    # historical evidence and never persists raw external credentials.
    memory_summary: Annotated[dict[str, Any], merge_dicts]
    memory_feedback: Annotated[list[dict[str, Any]], merge_lists]

    # V8 P0 A2: Rabbit Hole → Strategist closed loop counter.
    #
    # Bounded re-entry cap. The graph's `route_after_rabbit_hole`
    # conditional edge inspects this counter to decide whether to
    # route new RABBIT_HOLE-origin hypotheses back to the Strategist
    # for promotion, or to fall through to cvss_engine (the previous
    # one-directional behaviour). The Strategist on re-entry filters
    # to RABBIT_HOLE-origin hypotheses only — heuristic and cross-
    # reasons hypotheses already decided in the first pass are not
    # re-processed.
    #
    # The cap itself (max_loop_back_iterations) lives in
    # RabbitHolePolicy (config/policies.py) — default 1 — so operators
    # can tune it via policy overrides. This state field is just the
    # counter; the Strategist increments it on every re-entry pass.
    rabbit_hole_loop_back_count: int

    # V10 P0-2 Option A: thread_id stamped into state so the validator
    # can look up the sealed re-auth secret in the worker-only vault
    # (src/webpent/auth/reauth_vault.py) when FIX-10 has scrubbed
    # ``credentials["password"]`` from the checkpoint. Set once by
    # the worker (pentest_worker.run_pentest_task) in initial_state;
    # no node modifies it. Treated as last-write-wins (no reducer) —
    # same pattern as ``current_phase``, ``stealth_mode``, etc.
    #
    # Not sensitive: thread_id is already in the LangGraph config
    # (configurable.thread_id), already in Celery task kwargs, and
    # already in DB rows (findings.thread_id). Persisting it in state
    # does not expand the disclosure surface.
    thread_id: str
    # Cross-engagement lesson isolation identifiers. Optional for legacy
    # checkpoints; lesson retrieval fails closed when either value is absent.
    client_id: str | None
    engagement_id: str | None
