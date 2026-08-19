# src/webpent/agents/rabbit_hole/agent.py
"""webpent.agents.rabbit_hole.agent

V7 Cognitive Upgrade — Phase 7: Rabbit Hole (capstone).

Recursive follow-up of discovered artifacts. The mechanism most
directly analogous to :mod:`webpent.agents.exploit_chainer`, scaled
up and made explicitly safe.

Walking the example chain from the plan
(admin panel -> backup.zip -> docker-compose.yml -> Postgres creds
-> git repo -> secrets -> internal IPs):

**Trigger point (Section 5).** New artifacts show up in the Mental
Model from the normal discovery nodes (crawler, deep-probing agents,
and — critically — from post-exploitation enumeration once a finding
is confirmed, since that's realistically where a ``backup.zip`` or
``.git`` directory gets noticed). This is the equivalent of
``exploit_chainer``'s "look at what's already confirmed and ask if
two things combine" — except Rabbit Hole looks at *artifacts*, not
*finding pairs*.

**Deterministic classification gate (not LLM).** The
:data:`webpent.shared.cognitive_components.ARTIFACT_FOLLOW_PATTERNS`
table checks: is this artifact type one we know how to safely and
usefully follow? If it doesn't match a known pattern, nothing happens
— no LLM is asked to freely speculate about arbitrary files. This
mirrors ``_CHAIN_PATTERNS`` exactly: the "can we even consider this"
question is answered by plain Python before any model call happens.

**Loop Prevention check.** Before anything else, the artifact's
normalized identity (canonical URL / content hash / credential
fingerprint) is checked against ``state["rabbit_hole_ledger"]``.
Already visited -> stop, log it, done. This is the direct
generalization of ``exploit_chainer._already_proposed_pairs``.

**Risk Manager check.** Current branch depth vs.
``RabbitHolePolicy.max_depth``; total branches so far vs.
``max_branches``; does this discovery category (credentials, apparent
production data, out-of-scope-looking host) require a forced HITL
pause regardless of ``auto_approve``? Any failure here stops the
branch — fail-closed, exactly like ``scope_enforcer``'s existing
kill-switch design.

**Scope re-check — the single most important gate.** If the artifact
resolves to a *new host*, it must be run through the same logic
``scope_enforcer``/``Target.is_in_scope()`` already applies once,
today, right after the crawler. Rabbit Hole's loop-back path
explicitly re-invokes this check for every newly discovered host
before that host can be treated as investigable. If it's out of
scope, the discovery is recorded (Decision Log, Mental Model, marked
``in_scope=False``) but is never pursued.

**LLM's role — narrow, and only after every gate above already
passed.** Exactly like ``exploit_chainer._draft_chain_scenario``:
once a candidate has cleared classification, loop-prevention, risk,
and scope, the LLM's only job is to draft a short description of
*what to do next* — it does not decide whether to proceed, and it
cannot invent a follow-up action outside the artifact-pattern
table's known action types.

**No new, less-scrutinized execution path.** Rabbit Hole never
executes anything itself. A resulting action is either (a) a
genuinely read-only, safe, deterministic parse/extract step, or
(b) a new ``Hypothesis``/``Finding`` that re-enters the **existing**
pipeline at the appropriate point — a new host goes back through
``scope_enforcer -> recon``, a new endpoint goes through
``hypothesis``, a new credential pair to test goes through
``payload_generator``. Every one of those re-entry points still
passes through ``execution_sandbox``, which is still HITL-gated on
every single pass.

**Depth and branch caps enforce natural termination.** When a cap is
hit, the branch is marked ``abandoned`` in the Goal Tree, logged, and
the graph proceeds to the next-priority item instead — this is the
*normal*, expected termination path.
``settings.max_graph_steps`` / ``GraphRecursionError`` remains as the
outer safety net for the pathological case.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.config.policies import RabbitHolePolicy
from webpent.models.findings import VulnClass
from webpent.models.goal_tree import (
    GoalType,
    count_goal_nodes,
    create_rabbit_hole_branch_goal,
    curiosity_budget_consumed,
    find_root_goal_id,
)
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
from webpent.models.mental_model import (
    NodeKind,
    _coerce_to_mental_model,
    classify_artifact_type,
    extract_mental_model_updates,
)
from webpent.shared.adaptive_hunt import build_adaptive_hunt_update
from webpent.shared.cognitive_components import (
    FollowableArtifactType,
    check_loop_prevention,
    classify_followable_artifact,
    estimate_action_cost,
    record_visited_asset,
)
from webpent.shared.confidence import compute_initial_hypothesis_confidence
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — bounded loops, hard caps.
# ---------------------------------------------------------------------------
# Per Phase 7: "Depth and branch caps enforce natural termination."
# These are the inner-loop bounds specific to THIS node's scan pass.
# The engagement-wide caps live in RabbitHolePolicy and are checked
# per-branch by _check_risk_manager.

# Maximum number of artifact candidates this node will examine in a
# single pass. Mirrors exploit_chainer's _MAX_PAIRS_EXAMINED pattern —
# a hard, unconditional cap independent of how many artifacts exist.
_MAX_ARTIFACTS_EXAMINED = 20

# Maximum number of new Hypotheses this node will emit in a single
# pass. Mirrors exploit_chainer's _MAX_CHAINS_PROPOSED.
_MAX_BRANCHES_PER_PASS = 3



def _infer_rabbit_hole_vuln_class(artifact_type: str, action_type: str) -> str:
    """V10 AUDIT FIX (H3): infer an exploitable vuln_class for a Rabbit
    Hole hypothesis from the artifact type and action type.

    Previously ALL Rabbit Hole hypotheses got ``vuln_class=UNKNOWN``,
    which is NOT in ``EXPLOITABLE_CLASSES`` — so the Strategist's
    ``promote_hypothesis_to_finding`` blocked them. The entire Rabbit
    Hole → Strategist closed loop (V8 P0 A2) was functionally inert.

    This mapping is conservative: it assigns the closest exploitable
    class based on what the artifact IS, not what the vuln will turn
    out to be. The validator downstream will confirm or deny.
    """
    at = (artifact_type or "").lower()
    act = (action_type or "").lower()
    # Credential artifacts → the Rabbit Hole found creds; the likely
    # vuln is auth bypass / broken access control. Map to the closest
    # exploitable class.
    if "credential" in at or "cred" in at or "secret" in at or "token" in at:
        return VulnClass.SSRF.value  # credentialed access to internal resources
    # Public backup/archive/log artifacts are disclosure candidates. Do not
    # turn a read-only artifact into SSRF merely because the follow-up action
    # is named fetch/parse; the downstream validator must inspect the response.
    if any(marker in at for marker in ("backup", "archive", "dump", "log", "artifact")):
        return VulnClass.INFO_DISCLOSURE.value
    # URL / endpoint artifacts → SSRF candidate (the URL might be
    # fetchable server-side).
    if "url" in at or "endpoint" in at or "link" in at:
        return VulnClass.SSRF.value
    # Command / config / shell artifacts → RCE candidate.
    if "command" in at or "cmd" in at or "shell" in at or "config" in at:
        return VulnClass.RCE.value
    # File path artifacts → LFI / path traversal candidate.
    if "file" in at or "path" in at or "dir" in at:
        return VulnClass.LFI.value
    # Source-code/configuration disclosure that is only being parsed is
    # evidence for an information-disclosure review, not proof of LFI.
    # Keep it outside EXPLOITABLE_CLASSES so the existing strategist cannot
    # promote a read-only artifact into a High AI-Assessed vulnerability.
    if "source_code" in at or "source-code" in at or at == "source":
        return VulnClass.INFO_DISCLOSURE.value
    # Service / port artifacts → SSRF candidate (internal service access).
    if "service" in at or "port" in at or "host" in at:
        return VulnClass.SSRF.value
    # Action-based fallbacks.
    if "exec" in act or "run" in act:
        return VulnClass.RCE.value
    if ("read_only" in act or "parse" in act) and "source" in at:
        return VulnClass.INFO_DISCLOSURE.value
    if "read" in act or "include" in act:
        return VulnClass.LFI.value
    if "fetch" in act or "request" in act:
        return VulnClass.SSRF.value
    # Default: SSRF is the safest fallback (Rabbit Hole artifacts are
    # typically about reaching internal resources).
    return VulnClass.SSRF.value


# ---------------------------------------------------------------------------
# Phase 7 Step 1: Trigger point — find followable artifacts in the Mental Model.
# ---------------------------------------------------------------------------
def _find_followable_artifacts(
    mental_model_state: Any,
    rabbit_hole_ledger: Any,
) -> list[dict[str, Any]]:
    """Scan the Mental Model for artifact nodes worth following.

    Per Section 5: "New artifacts show up in the Mental Model from
    the normal discovery nodes." This function scans the Mental
    Model's ``artifact`` and ``credential`` nodes, classifies each
    via the deterministic :data:`ARTIFACT_FOLLOW_PATTERNS` table,
    and returns the followable ones (those NOT already in the
    visited-assets ledger).

    Returns a list of dicts, each shaped::

        {
            "node_id": str,
            "identity_key": str,
            "artifact_type": str,        # e.g. "archive", "credential_string"
            "action_type": str,          # e.g. "download_and_parse_archive"
            "forced_hitl_category": str | None,
            "url": str,                  # the artifact's URL or source
            "node_metadata": dict,       # the Mental Model node's metadata
        }

    The list is capped at :data:`_MAX_ARTIFACTS_EXAMINED` entries —
    a hard, unconditional cap independent of how many artifacts exist.
    """
    model = _coerce_to_mental_model(mental_model_state)
    if not model.nodes:
        return []

    candidates: list[dict[str, Any]] = []
    examined = 0

    for node in model.nodes.values():
        if examined >= _MAX_ARTIFACTS_EXAMINED:
            break
        if len(candidates) >= _MAX_BRANCHES_PER_PASS:
            break

        # Only artifact and credential nodes are Rabbit Hole candidates.
        # Hosts/endpoints/services/technologies are not "followable
        # artifacts" — they're already-investigated assets.
        if node.kind not in (
            NodeKind.ARTIFACT.value,
            NodeKind.CREDENTIAL.value,
        ):
            continue

        examined += 1

        # Skip artifacts that are NOT in scope (scope_enforcer already
        # marked these; we never follow out-of-scope artifacts). None
        # means "not yet checked" — treat as not-yet-followable (the
        # scope re-check gate below will handle it).
        if node.in_scope is False:
            continue

        # Classify the artifact type via the Mental Model node's
        # metadata, then look up the follow pattern.
        node_meta = node.metadata or {}
        artifact_type: str | None = None

        if node.kind == NodeKind.ARTIFACT.value:
            # Artifact nodes carry their type in metadata["type"].
            artifact_type = node_meta.get("type") or classify_artifact_type(
                node_meta.get("url", "")
            )
        elif node.kind == NodeKind.CREDENTIAL.value:
            # Credential nodes are always "credential_string" for
            # follow-table purposes.
            artifact_type = FollowableArtifactType.CREDENTIAL_STRING.value

        if not artifact_type:
            continue

        follow_info = classify_followable_artifact(artifact_type)
        if follow_info is None:
            # Not a known followable type — skip (per Section 5: "If
            # it doesn't match a known pattern, nothing happens").
            continue

        followable, action_type, forced_hitl_category = follow_info
        if not followable:
            continue

        # Loop Prevention: skip if already visited.
        if check_loop_prevention(rabbit_hole_ledger, node.identity_key):
            logger.debug(
                "Rabbit Hole: skipping already-visited artifact %s",
                node.identity_key,
            )
            continue

        candidates.append({
            "node_id": node.id,
            "identity_key": node.identity_key,
            "artifact_type": artifact_type,
            "action_type": action_type,
            "forced_hitl_category": forced_hitl_category,
            "url": node_meta.get("url", node.identity_key),
            "node_metadata": dict(node_meta),
        })

    return candidates


# ---------------------------------------------------------------------------
# Phase 7 Step 5: Scope re-check — the single most important gate.
# ---------------------------------------------------------------------------
def _scope_check_new_host(
    target: Any,
    url: str,
) -> tuple[bool, str | None]:
    """Re-invoke the scope check for a newly discovered host.

    Per Section 5: "If the artifact resolves to a *new host*, it must
    be run through the same logic ``scope_enforcer``/
    ``Target.is_in_scope()`` already applies once, today, right after
    the crawler. Rabbit Hole's loop-back path must explicitly re-invoke
    this check for every newly discovered host before that host can be
    treated as investigable."

    Per Section 6: "Scope escape is the primary new risk this feature
    introduces, and it's the one to design most defensively against.
    Every newly discovered host must pass through an explicit,
    deterministic scope check before being treated as investigable —
    no exceptions, no 'the LLM judged it was probably related to the
    target.' This directly extends ``scope_enforcer``'s existing
    fail-closed kill-switch design."

    Args:
        target: The engagement's :class:`Target` instance.
        url: The URL to scope-check.

    Returns:
        A tuple of ``(in_scope, hostname)``. ``in_scope`` is True
        only if ``target.is_in_scope(url)`` returned True. Any
        exception during the scope check returns ``(False, hostname)``
        — fail-closed, exactly like ``scope_enforcer``.
    """
    if not url:
        return False, None
    try:
        hostname = urlparse(url).hostname
    except Exception:
        return False, None
    if not hostname:
        return False, None
    try:
        in_scope = target.is_in_scope(url)
    except Exception as exc:
        # Fail-closed — any scope-check exception = NOT in scope.
        # Mirrors scope_enforcer's V4.5 Kill-Switch design.
        logger.warning(
            "Rabbit Hole scope re-check FAILED for %s (host=%s): %s — "
            "fail-closed (treating as out-of-scope).",
            url, hostname, exc,
        )
        return False, hostname
    return bool(in_scope), hostname


# ---------------------------------------------------------------------------
# Phase 7 Step 4: Risk Manager check.
# ---------------------------------------------------------------------------
def _check_risk_manager(
    policy: RabbitHolePolicy,
    *,
    current_depth: int,
    current_branches: int,
    curiosity_budget_consumed: float,
) -> str | None:
    """Check RabbitHolePolicy caps. Return a reason string if a cap is hit.

    Pure Python — no LLM. Any cap hit returns a non-None reason,
    which causes the caller to skip the branch (fail-closed).

    Args:
        policy: The :class:`RabbitHolePolicy` to check against.
        current_depth: The current branch's depth.
        current_branches: The engagement's total branch count so far.
        curiosity_budget_consumed: The curiosity budget consumed so
            far (as a fraction in [0, 1]).

    Returns:
        A reason string if a cap is hit, else None.
    """
    if current_depth >= policy.max_depth:
        return f"depth {current_depth} >= max_depth {policy.max_depth}"
    if current_branches >= policy.max_branches:
        return f"branches {current_branches} >= max_branches {policy.max_branches}"
    if curiosity_budget_consumed >= policy.curiosity_budget_ceiling:
        return (
            f"curiosity_budget {curiosity_budget_consumed:.2f} >= "
            f"ceiling {policy.curiosity_budget_ceiling:.2f}"
        )
    return None


# ---------------------------------------------------------------------------
# Phase 7 Step 6: Narrow LLM role — draft "what to do next".
# ---------------------------------------------------------------------------
_RABBIT_HOLE_LLM_SYSTEM_PROMPT = (
    "You are drafting a CANDIDATE next-step description for a "
    "human-reviewed, HITL-gated pentest pipeline's Rabbit Hole "
    "recursive-follow-up feature. You are given an artifact that has "
    "ALREADY cleared deterministic classification, loop-prevention, "
    "risk-manager, and scope-re-check gates. Your job is ONLY to write "
    "a 1-2 sentence description of what to do next with this artifact "
    "(e.g. 'extract this archive and scan its contents for "
    "credential-shaped strings'). Do NOT decide whether to proceed — "
    "that decision was already made deterministically. Do NOT invent a "
    "follow-up action outside the stated action type. The resulting "
    "Hypothesis will go through the EXACT same "
    "execution_sandbox (human-approval-gated) -> validator -> "
    "devils_advocate pipeline as any other finding before it is "
    "trusted."
)

_RABBIT_HOLE_LLM_HUMAN_TEMPLATE = (
    "Artifact type: {artifact_type}\n"
    "Action type (already deterministically selected): {action_type}\n"
    "Artifact URL/identity: {url}\n"
    "Branch depth: {depth}\n\n"
    "Draft a 1-2 sentence description of what to do next with this "
    "artifact. The description will become a Hypothesis statement."
)


def _draft_next_step_description(
    *,
    artifact_type: str,
    action_type: str,
    url: str,
    depth: int,
    llm: Any,
) -> str | None:
    """Ask the LLM to draft a 1-2 sentence 'what to do next' description.

    Per Section 5: "the LLM's only job is to draft a short description
    of *what to do next* — it does not decide whether to proceed, and
    it cannot invent a follow-up action outside the artifact-pattern
    table's known action types."

    Returns ``None`` on any LLM failure — a candidate that fails to
    draft is simply dropped, not retried indefinitely (no unbounded
    retry loop, mirroring ``exploit_chainer._draft_chain_scenario``).
    """
    try:
        from webpent.shared.llm import (
            get_safety_system_instruction,
            safe_prompt_format,
        )
    except Exception as exc:
        logger.debug("Rabbit Hole LLM helper import failed: %s", exc)
        return None

    try:
        human_prompt = safe_prompt_format(
            _RABBIT_HOLE_LLM_HUMAN_TEMPLATE,
            artifact_type=artifact_type,
            action_type=action_type,
            url=url[:300],
            depth=depth,
        )
        response = llm.invoke([
            SystemMessage(content=get_safety_system_instruction()),
            SystemMessage(content=_RABBIT_HOLE_LLM_SYSTEM_PROMPT),
            HumanMessage(content=human_prompt),
        ])
        text = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
        # Truncate to Hypothesis.statement max_length.
        return text.strip()[:500] if text.strip() else None
    except Exception as exc:
        logger.debug("Rabbit Hole LLM draft failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Phase 7: The Rabbit Hole node.
# ---------------------------------------------------------------------------
def rabbit_hole_node(state: PentestState) -> dict[str, Any]:
    """LangGraph node: Rabbit Hole recursive follow-up of discovered artifacts.

    Per Section 5: this node scans the Mental Model for followable
    artifacts, runs each through the deterministic classification ->
    loop-prevention -> risk-manager -> scope-re-check gate sequence,
    and (only if all gates pass) asks the LLM to draft a short
    next-step description. The draft becomes a new :class:`Hypothesis`
    that re-enters the existing pipeline at the appropriate point
    (``payload_generator`` for credential tests, ``hypothesis`` for
    new endpoints, ``scope_enforcer -> recon`` for new hosts).

    The node NEVER executes anything itself — it only emits
    Hypotheses and Goal Tree branch goals. Every resulting action
    still passes through ``execution_sandbox``, which is still
    HITL-gated on every single pass.

    Returns a partial state update with:
      * ``hypotheses`` — new :class:`Hypothesis` objects (one per
        followed artifact, capped at :data:`_MAX_BRANCHES_PER_PASS`).
      * ``rabbit_hole_ledger`` — visited-asset ledger updates
        (records each followed artifact's identity_key).
      * ``goal_tree`` — new RABBIT_HOLE_BRANCH goal nodes + budget
        increments.
      * ``decision_log`` — Decision Log entries for every gate
        decision (entered, blocked, abandoned).
      * ``messages`` — a summary :class:`AIMessage`.
      * ``current_phase`` — set to ``"rabbit_hole"``.
    """
    target = state.get("target")
    mental_model_state = state.get("mental_model") or {}
    rabbit_hole_ledger = state.get("rabbit_hole_ledger") or {}
    goal_tree_state = state.get("goal_tree") or {}

    # Phase 6 is additive: it schedules bounded revisit tasks but never
    # executes them. When the feature flag is off this returns {}, preserving
    # the legacy Rabbit-Hole path byte-for-byte at the state contract level.
    adaptive_update = build_adaptive_hunt_update(state)

    # Load the RabbitHolePolicy (Phase 6). Use defaults if construction
    # fails — fail-safe (the default policy is maximally conservative).
    try:
        policy = RabbitHolePolicy()
    except Exception as exc:
        # V10 P3-2 FIX: previously this except block re-constructed
        # RabbitHolePolicy() — the SAME call that just failed — so the
        # same exception fired again and crashed the node. Fail-closed
        # instead: log ERROR and return an empty state update so the
        # graph continues without emitting any rabbit-hole hypotheses
        # or branches. (No cap check runs because we never reach the
        # per-candidate loop.)
        logger.error(
            "Rabbit Hole: RabbitHolePolicy construction failed (%s) — "
            "aborting rabbit-hole pass (fail-closed, no new branches "
            "will be created this pass).", exc,
        )
        return {}

    # Count current branches in the Goal Tree (for the max_branches cap).
    current_branches = _count_rabbit_hole_branches(goal_tree_state)

    # Approximate curiosity budget consumed as the fraction of total
    # Goal Tree budget consumed by rabbit-hole branch goals. This is
    # a conservative approximation — the real budget tracker is the
    # Goal Tree node's budget_consumed field, accumulated across the
    # engagement. Phase 6's increment_budget_consumed helper keeps it
    # up to date.
    curiosity_budget_consumed = _estimate_curiosity_budget_consumed(goal_tree_state)

    # Step 1: Find followable artifacts in the Mental Model.
    candidates = _find_followable_artifacts(mental_model_state, rabbit_hole_ledger)
    if not candidates:
        logger.info("Rabbit Hole: no followable artifacts found — skipping.")
        return {
            **adaptive_update,
            "messages": [AIMessage(content="Rabbit Hole: no followable artifacts.")],
            "current_phase": "rabbit_hole",
        }

    logger.info(
        "Rabbit Hole: %d followable artifact candidate(s) found.",
        len(candidates),
    )

    # Get an LLM for drafting next-step descriptions. Per Section 5,
    # the LLM is ONLY consulted after all gates pass — we get it
    # upfront but only invoke it inside the per-candidate loop.
    try:
        from webpent.shared.llm import TaskType, try_get_llm
        llm = try_get_llm(TaskType.ANALYSIS)
    except Exception as exc:
        logger.warning("Rabbit Hole: LLM unavailable (%s) — drafts will be empty.", exc)
        llm = None

    new_hypotheses: list[Hypothesis] = []
    ledger_updates: dict[str, Any] = {}
    goal_tree_updates: dict[str, Any] = {"nodes": {}}
    mental_model_updates: dict[str, Any] = {"nodes": {}, "edges": []}
    decision_log_updates: list[dict[str, Any]] = []
    branches_entered = 0
    branches_blocked = 0

    for candidate in candidates:
        if branches_entered >= _MAX_BRANCHES_PER_PASS:
            break

        identity_key = candidate["identity_key"]
        artifact_type = candidate["artifact_type"]
        action_type = candidate["action_type"]
        forced_hitl_category = candidate["forced_hitl_category"]
        url = candidate["url"]

        # Step 4: Risk Manager check.
        # Depth for this candidate = current branch count (each new
        # branch starts at depth 0; deeper recursion is tracked by
        # the Goal Tree's branch_depth metadata in future passes).
        risk_reason = _check_risk_manager(
            policy,
            current_depth=current_branches,  # conservative: treat as depth
            current_branches=current_branches,
            curiosity_budget_consumed=curiosity_budget_consumed,
        )
        if risk_reason is not None:
            branches_blocked += 1
            _log_rabbit_hole_decision(
                decision_log_updates,
                decision_type="risk_gate_blocked",
                rule_fired=f"risk_manager: {risk_reason}",
                outcome="blocked",
                entity_refs=[candidate["node_id"]],
                branch_id=candidate["node_id"],
            )
            logger.info(
                "Rabbit Hole: blocked artifact %s — risk manager: %s",
                identity_key, risk_reason,
            )
            continue

        # Step 5: Scope re-check — only for artifacts that resolve to a
        # new host (the single most important gate per Section 5/6).
        # For artifacts on the SAME host as the target (e.g. a
        # backup.zip on the already-in-scope target host), the scope
        # check is implicitly satisfied (the Mental Model node's
        # in_scope field was set by scope_enforcer). For artifacts
        # that resolve to a DIFFERENT host, we re-invoke is_in_scope.
        in_scope = True
        scope_hostname: str | None = None
        if url and url.startswith(("http://", "https://")):
            in_scope, scope_hostname = _scope_check_new_host(target, url)
            if not in_scope:
                branches_blocked += 1
                _log_rabbit_hole_decision(
                    decision_log_updates,
                    decision_type="scope_check",
                    rule_fired=(
                        f"scope_re_check: host={scope_hostname} "
                        f"NOT in scope — fail-closed"
                    ),
                    outcome="blocked_out_of_scope",
                    entity_refs=[candidate["node_id"]],
                    branch_id=candidate["node_id"],
                )
                logger.info(
                    "Rabbit Hole: blocked artifact %s — out of scope "
                    "(host=%s). Recorded in Mental Model as in_scope=False.",
                    identity_key, scope_hostname,
                )
                # Record the out-of-scope discovery in the Mental Model
                # (marked in_scope=False) so it surfaces in the report
                # as "found something interesting, but it's out of scope"
                # rather than silently vanishing (per Section 5).
                mental_model_update = extract_mental_model_updates(
                    discovery_source="rabbit_hole_node:out_of_scope",
                    hosts=[scope_hostname] if scope_hostname else None,
                    target_url=url,
                )
                # Mark the host node in_scope=False.
                for _nid, node_dict in (mental_model_update.get("nodes") or {}).items():
                    if node_dict.get("kind") == NodeKind.HOST.value:
                        node_dict["in_scope"] = False
                # V7 Phase 7 FIX (audit): write to mental_model_updates,
                # NOT goal_tree_updates. The Mental Model node dicts have
                # a different shape than GoalTreeNode dicts — writing
                # them to goal_tree corrupts the Goal Tree.
                mental_model_updates.update(mental_model_update)
                continue

        # Forced HITL check: if the artifact's category forces HITL
        # (credentials, apparent production data), record a Decision
        # Log entry. The actual HITL pause is inherited from
        # execution_sandbox (per Section 6: "HITL is inherited, not
        # re-implemented") — we don't add a new interrupt here. The
        # resulting Hypothesis, when promoted, will go through
        # payload_generator -> execution_sandbox which is already
        # HITL-gated.
        if forced_hitl_category and policy.requires_forced_hitl(forced_hitl_category):
            _log_rabbit_hole_decision(
                decision_log_updates,
                decision_type="risk_gate_blocked",
                rule_fired=(
                    f"forced_hitl: category={forced_hitl_category} "
                    f"requires mandatory HITL pause (inherited from "
                    f"execution_sandbox)"
                ),
                outcome="requires_hitl",
                entity_refs=[candidate["node_id"]],
                branch_id=candidate["node_id"],
            )
            logger.info(
                "Rabbit Hole: artifact %s category %s forces HITL — "
                "the resulting Hypothesis will pause at execution_sandbox.",
                identity_key, forced_hitl_category,
            )

        # Step 6: Narrow LLM role — draft next-step description.
        # Per Section 5: ONLY after all gates above passed.
        draft_description = None
        if llm is not None:
            draft_description = _draft_next_step_description(
                artifact_type=artifact_type,
                action_type=action_type,
                url=url,
                depth=current_branches,
                llm=llm,
            )

        if not draft_description:
            # LLM unavailable or draft failed — use a deterministic
            # fallback description based on the action_type. Per
            # Section 5: the LLM "cannot invent a follow-up action
            # outside the artifact-pattern table's known action types"
            # — so the fallback is just the action_type description.
            draft_description = (
                f"Follow {artifact_type} at {url[:100]} via "
                f"{action_type} (deterministic fallback — LLM draft "
                f"unavailable)."
            )

        # Create the new Hypothesis. Per Section 5: "a new Hypothesis
        # that re-enters the existing pipeline at the appropriate
        # point." The Hypothesis's origin is RABBIT_HOLE, with
        # parent_hypothesis_id tracking the chain (None for top-level
        # Rabbit Hole hypotheses — the parent is the artifact, not a
        # prior hypothesis).
        # Estimate cost from the action_type lookup table (Phase 6).
        estimated_cost = estimate_action_cost(action_type)

        # Derive a vuln_class for the new Hypothesis.
        # V10 AUDIT FIX (H3): previously ALL Rabbit Hole hypotheses got
        # vuln_class=UNKNOWN, which is NOT in EXPLOITABLE_CLASSES — so
        # the Strategist's promote_hypothesis_to_finding (prioritization.py)
        # blocked them. The entire Rabbit Hole → Strategist closed loop
        # (V8 P0 A2) was functionally inert. Fix: infer a vuln_class
        # from the artifact type / action. Credential artifacts →
        # AUTH_BYPASS (mapped to the closest exploitable class). URL
        # artifacts → SSRF. Command/config artifacts → RCE. File path
        # artifacts → LFI. This makes Rabbit Hole hypotheses promotable.
        _rh_vuln_class = _infer_rabbit_hole_vuln_class(artifact_type, action_type)
        new_hypothesis = Hypothesis(
            target_url=url,
            statement=draft_description,
            vuln_class=_rh_vuln_class,
            origin=HypothesisOrigin.RABBIT_HOLE.value,
            origin_detail=(
                f"Rabbit Hole branch from artifact {identity_key} "
                f"(type={artifact_type}, action={action_type}). "
                f"Forced HITL category: {forced_hitl_category or 'none'}."
            ),
            confidence_score=compute_initial_hypothesis_confidence(
                HypothesisOrigin.RABBIT_HOLE,
                source_kind="rag_informed",
            ),
            estimated_cost=estimated_cost,
            parent_hypothesis_id=None,  # top-level Rabbit Hole hypothesis
            # RAG/LLM-informed rabbit-hole branches are research proposals,
            # not deterministic validators. They must pass the normal causal
            # signal and negative-control gates before promotion.
            deterministic_match=False,
        )
        new_hypotheses.append(new_hypothesis)

        # Record the artifact as visited in the ledger (Loop Prevention).
        ledger_update = record_visited_asset(
            rabbit_hole_ledger,
            identity_key,
            discovery_source="rabbit_hole_node",
            branch_id=str(new_hypothesis.id),
        )
        ledger_updates.update(ledger_update)

        # Create a Goal Tree branch goal for this Rabbit Hole branch.
        branch_goal = create_rabbit_hole_branch_goal(
            parent_id=_find_root_goal_id(goal_tree_state) or "root",
            label=f"rabbit_hole:{artifact_type}@{url[:60]}",
            branch_depth=current_branches,
            parent_hypothesis_id=str(new_hypothesis.id),
            trigger_artifact_identity=identity_key,
            budget_remaining=policy.max_actions_per_branch,
        )
        goal_tree_updates["nodes"][branch_goal.id] = branch_goal.model_dump(mode="json")

        # Log the branch entry.
        _log_rabbit_hole_decision(
            decision_log_updates,
            decision_type="rabbit_hole_entered",
            rule_fired=(
                f"classification={artifact_type}, loop_prevention=not_visited, "
                f"risk=ok, scope={'in' if in_scope else 'out'}, "
                f"forced_hitl={forced_hitl_category or 'none'}"
            ),
            outcome="entered",
            entity_refs=[candidate["node_id"], str(new_hypothesis.id)],
            branch_id=str(new_hypothesis.id),
        )

        branches_entered += 1
        current_branches += 1

    # Compose the summary.
    summary = (
        f"Rabbit Hole completed: examined {len(candidates)} artifact(s), "
        f"entered {branches_entered} branch(es), blocked {branches_blocked}."
    )
    logger.info(summary)

    merged_decision_log = [
        *(adaptive_update.get("decision_log") or []),
        *decision_log_updates,
    ]
    return {
        **adaptive_update,
        "hypotheses": new_hypotheses,
        "rabbit_hole_ledger": ledger_updates,
        "goal_tree": goal_tree_updates,
        "mental_model": mental_model_updates,
        "decision_log": merged_decision_log,
        "messages": [AIMessage(content=summary)],
        "current_phase": "rabbit_hole",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _count_rabbit_hole_branches(goal_tree_state: Any) -> int:
    """Compatibility wrapper around the canonical GoalTree counter."""
    return count_goal_nodes(goal_tree_state, GoalType.RABBIT_HOLE_BRANCH)


def _estimate_curiosity_budget_consumed(goal_tree_state: Any) -> float:
    """Compatibility wrapper around the canonical GoalTree budget ratio."""
    return curiosity_budget_consumed(goal_tree_state)


def _find_root_goal_id(goal_tree_state: Any) -> str | None:
    """Compatibility wrapper around the canonical GoalTree root selector."""
    return find_root_goal_id(goal_tree_state)


def _log_rabbit_hole_decision(
    decision_log_updates: list[dict[str, Any]],
    *,
    decision_type: str,
    rule_fired: str,
    outcome: str,
    entity_refs: list[str] | None = None,
    branch_id: str | None = None,
) -> None:
    """Append a Decision Log entry to the in-state update list.

    Also persists to the SQLite decision_log table via the Phase 6
    manager (best-effort, non-fatal on failure).
    """
    from datetime import datetime, timezone
    from uuid import uuid4
    entry_dict = {
        "id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision_type": decision_type,
        "rule_fired": rule_fired,
        "outcome": outcome,
        "llm_contribution": "",
        "entity_refs": list(entity_refs or []),
        "branch_id": branch_id,
        "metadata": {},
    }
    decision_log_updates.append(entry_dict)

    # Best-effort persistence to the SQLite table (Phase 6).
    try:
        from webpent.memory.decision_log import log_decision
        log_decision(
            decision_type=decision_type,
            rule_fired=rule_fired,
            outcome=outcome,
            entity_refs=list(entity_refs or []),
            branch_id=branch_id,
        )
    except Exception as exc:
        logger.debug(
            "Rabbit Hole Decision Log persistence failed (non-fatal): "
            "type=%s exc=%s",
            decision_type, exc,
        )
