# src/webpent/graph/builder.py
"""LangGraph orchestration for WebPent.

The compiled graph contains **31 base nodes**. ``attack_graph`` is an
additional node when ``enable_attack_graph`` is enabled. ``START`` and
``END`` are pseudo-nodes and are not included in that count.

The graph is intentionally divided into readable stages:

* **Engagement setup:** ``planner`` -> ``auth``.
* **Recon and understanding:** optional ``recon``/``crawler`` path, static
  JavaScript intelligence, infrastructure checks, optional target
  understanding, scope enforcement, and WAF detection.
* **Hypothesis and deep probes:** ``hypothesis`` -> access-control, API,
  business-logic, request-smuggling, disclosed-report intelligence, optional
  attack graph, and ``strategist``.
* **Evidence pipeline:** ``payload_generator`` -> HITL-gated
  ``execution_sandbox`` -> ``validator`` -> bounded optimizer retries or
  ``devils_advocate``.
* **Post-validation reasoning:** ``exploit_chainer`` and ``rabbit_hole``
  feed only bounded loops back into the evidence pipeline; scoring, impact,
  cross-reasoning, executive summary, reporting, and reflection finish the
  engagement.

Conditional paths are fail-closed and feature-flagged. ``skip_recon`` can
bypass network reconnaissance, but it does not bypass the strategist or
validator when open hypotheses or findings exist. The ``route_after_hypothesis``
name is the canonical name; ``route_after_recon`` remains a compatibility
alias for older callers.

All loops are bounded by ``_MAX_OPTIMIZATION_RETRIES``, the rabbit-hole policy,
and the existing evidence/approval contracts. ``interrupt_before`` is placed
before ``execution_sandbox`` unless ``auto_approve=True``.
"""


from __future__ import annotations

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from webpent.agents.access_control.agent import access_control_node
from webpent.agents.api_testing.agent import api_testing_node
from webpent.agents.attack_graph.agent import attack_graph_node
from webpent.agents.authentication.agent import auth_node
from webpent.agents.business_impact.agent import business_impact_node
from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node
from webpent.agents.cloud_storage.agent import cloud_storage_node
from webpent.agents.crawler.agent import crawler_node
from webpent.agents.cross_reasoning.agent import cross_reasoning_node
from webpent.agents.cvss_engine.agent import cvss_node
from webpent.agents.devils_advocate.agent import devils_advocate_node
from webpent.agents.disclosed_report_intel.agent import disclosed_report_intel_node
from webpent.agents.execution_sandbox.agent import execution_sandbox_node
from webpent.agents.executive_summary.agent import executive_summary_node
from webpent.agents.exploit_chainer.agent import exploit_chainer_node
from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.agents.javascript_intelligence.agent import javascript_intelligence_node
from webpent.agents.payload_generator.agent import payload_generator_node
from webpent.agents.payload_optimizer.agent import payload_optimizer_node
from webpent.agents.planner.agent import planner_node
from webpent.agents.post_exploit.agent import post_exploitation_node
from webpent.agents.rabbit_hole.agent import rabbit_hole_node
from webpent.agents.recon.agent import recon_node
from webpent.agents.reflection.agent import reflection_node
from webpent.agents.reporter.agent import reporter_node, reporter_node_bug_bounty
from webpent.agents.request_smuggling.agent import request_smuggling_node
from webpent.agents.scope_enforcer.agent import scope_enforcer_node
from webpent.agents.smart_campaigns.agent import (
    smart_campaigns_execution_node,
    smart_campaigns_node,
)
from webpent.agents.strategist.agent import strategist_node
from webpent.agents.subdomain_takeover.agent import subdomain_takeover_node
from webpent.agents.target_understanding.agent import target_understanding_node
from webpent.agents.validator.agent import validator_node
from webpent.agents.waf_detector.agent import waf_detector_node
from webpent.config.settings import get_settings
from webpent.models.findings import (
    EXPLOITABLE_CLASSES,
    Confidence,
    Finding,
    Severity,
)
from webpent.shared.autonomous_controller import autonomous_controller_node
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

NODE_PLANNER = "planner"
NODE_AUTH = "auth"
NODE_RECON = "recon"
NODE_CRAWLER = "crawler"
NODE_SCOPE_ENFORCER = "scope_enforcer"
NODE_WAF_DETECTOR = "waf_detector"
NODE_HYPOTHESIS = "hypothesis"
NODE_PAYLOAD_GENERATOR = "payload_generator"
NODE_EXECUTION_SANDBOX = "execution_sandbox"
NODE_VALIDATOR = "validator"
NODE_DEVILS_ADVOCATE = "devils_advocate"
# V7 "Apex Predator" addition: chains confirmed findings into candidate
# combined-exploit scenarios. Sits after devils_advocate (only chains
# from findings that survived debunking) and before post_exploitation.
NODE_EXPLOIT_CHAINER = "exploit_chainer"
NODE_POST_EXPLOITATION = "post_exploitation"
# V7 Cognitive Upgrade Phase 7: Rabbit Hole — runs after post_exploitation
# (where artifacts realistically get noticed via safe read-only enumeration)
# and before cvss_engine. Emits new Hypotheses that re-enter the existing
# payload_generator -> execution_sandbox (HITL-gated) -> validator pipeline.
NODE_RABBIT_HOLE = "rabbit_hole"
# V7 Cognitive Upgrade Section 4: Strategist — promotion checkpoint.
# Runs after all discovery nodes, before payload_generator. Promotes
# high-scoring hypotheses to Findings so the existing pipeline can
# process them. Bounded: can only rank+recommend, cannot authorize
# execution or expand scope (per Section 4).
NODE_STRATEGIST = "strategist"
NODE_PAYLOAD_OPTIMIZER = "payload_optimizer"
NODE_CVSS_ENGINE = "cvss_engine"
NODE_BUSINESS_IMPACT = "business_impact"
NODE_CROSS_REASONING = "cross_reasoning"
NODE_EXECUTIVE_SUMMARY = "executive_summary"
NODE_REPORTER = "reporter"
NODE_REFLECTION = "reflection"

# V7 Sprint 2: New node names for the expanded vulnerability-coverage agents.
# These run as a "deep probing" phase between hypothesis and payload_generator.
NODE_ACCESS_CONTROL = "access_control"
NODE_ATTACK_GRAPH = "attack_graph"
NODE_API_TESTING = "api_testing"
NODE_BUSINESS_LOGIC_FUZZER = "business_logic_fuzzer"
NODE_REQUEST_SMUGGLING = "request_smuggling"
NODE_SUBDOMAIN_TAKEOVER = "subdomain_takeover"
NODE_CLOUD_STORAGE = "cloud_storage"
NODE_DISCLOSED_REPORT_INTEL = "disclosed_report_intel"
NODE_TARGET_UNDERSTANDING = "target_understanding"
NODE_JAVASCRIPT_INTELLIGENCE = "javascript_intelligence"
NODE_SMART_CAMPAIGNS = "smart_campaigns"
NODE_SMART_CAMPAIGNS_EXECUTION = "smart_campaigns_execution"
NODE_AUTONOMOUS_CONTROLLER = "autonomous_controller"

# V3.5 Obsidian Master: Import from central location (models/findings.py).
_EXPLOITABLE_CLASSES = EXPLOITABLE_CLASSES

_MIN_SEVERITY_VALUE = Severity.MEDIUM.value
_SEVERITY_RANKS: dict[str, int] = {
    Severity.INFO.value: 0, Severity.LOW.value: 1, Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3, Severity.CRITICAL.value: 4,
}

_MAX_OPTIMIZATION_RETRIES = 3


def _is_exploitable(finding: Finding) -> bool:
    """Return True if ``finding.vuln_class`` is in the exploitable set.

    V3.5: Replaces fragile keyword matching on titles/descriptions with
    a deterministic check on the ``vuln_class`` enum field.

    V10 EXHAUSTIVE AUDIT (P0-1): uses :func:`model_get` so it works on
    both Finding instances and plain dicts (after checkpoint round-trip).
    """
    from webpent.state.reducers import model_get
    vc = model_get(finding, "vuln_class")
    return vc in _EXPLOITABLE_CLASSES


def _meets_severity_threshold(finding: Finding) -> bool:
    from webpent.state.reducers import model_get
    rank = _SEVERITY_RANKS.get(str(model_get(finding, "severity", "")), 0)
    return rank >= _SEVERITY_RANKS[_MIN_SEVERITY_VALUE]


def _attack_graph_enabled() -> bool:
    """Return the additive Attack Graph flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_attack_graph)
    except Exception:
        return False


def _autonomous_controller_enabled(state: PentestState) -> bool:
    """Enable the bounded controller only through an explicit state flag."""
    return state.get("enable_autonomous_controller") is True


def _smart_campaigns_enabled(state: PentestState) -> bool:
    """Enable Smart Hunter only for an explicit non-legacy scan profile."""
    governance = state.get("smart_governance", {})
    profile = governance.get("profile") if isinstance(governance, dict) else None
    return bool(
        state.get("smart_mode")
        or state.get("enable_smart_campaigns")
        or profile in {
            "smart",
            "smart-observe",
            "safe-smart",
            "authorized-active",
            "vip-qualification",
        }
    )


def route_after_disclosed_report_intel(state: PentestState) -> str:
    """Preserve Attack Graph routing; otherwise enter Smart Hunter when opted in."""
    if _attack_graph_enabled():
        return NODE_ATTACK_GRAPH
    return NODE_SMART_CAMPAIGNS if _smart_campaigns_enabled(state) else NODE_STRATEGIST


def route_after_attack_graph(state: PentestState) -> str:
    """Continue from Attack Graph into Smart Hunter only when explicitly enabled."""
    return NODE_SMART_CAMPAIGNS if _smart_campaigns_enabled(state) else NODE_STRATEGIST


def route_after_smart_campaigns_execution(state: PentestState) -> str:
    """Bounded observation-driven replan route for the Smart Hunter adapter."""
    if _autonomous_controller_enabled(state):
        return NODE_AUTONOMOUS_CONTROLLER
    replanning = state.get("smart_replanning") or {}
    if not isinstance(replanning, dict):
        return NODE_STRATEGIST
    if replanning.get("replan_requested") is not True:
        return NODE_STRATEGIST
    try:
        current_round = int(replanning.get("round", 0))
        max_rounds = int(replanning.get("max_replan_rounds", 0))
    except (TypeError, ValueError):
        return NODE_STRATEGIST
    return NODE_SMART_CAMPAIGNS if current_round < max_rounds else NODE_STRATEGIST


def _target_understanding_enabled() -> bool:
    """Return the additive Target Understanding flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_target_understanding)
    except Exception:
        return False


def _js_intelligence_enabled() -> bool:
    """Return the optional static-JS intelligence flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_js_intelligence)
    except Exception:
        return False


def route_after_crawler(state: PentestState) -> str:
    """Run static JavaScript review only when explicitly enabled."""
    del state
    return NODE_JAVASCRIPT_INTELLIGENCE if _js_intelligence_enabled() else NODE_SUBDOMAIN_TAKEOVER


def route_after_infrastructure(state: PentestState) -> str:
    """Route through Target Understanding for configured or Smart scans."""
    smart_scan = _smart_campaigns_enabled(state)
    return (
        NODE_TARGET_UNDERSTANDING
        if _target_understanding_enabled() or smart_scan
        else NODE_SCOPE_ENFORCER
    )


def route_after_auth(state: PentestState) -> str:
    """V6.1: Conditional edge after AUTH — skip recon if requested.

    If ``skip_recon`` is True, bypass the recon/crawler/scope/waf
    pipeline and go straight to the hypothesis node (using the
    provided target URL as the sole endpoint).
    """
    if state.get("skip_recon"):
        logger.info("skip_recon=True — bypassing recon/crawler/scope/waf")
        if _target_understanding_enabled():
            return NODE_TARGET_UNDERSTANDING
        return NODE_HYPOTHESIS
    return NODE_RECON


def route_after_hypothesis(state: PentestState) -> str:
    """Conditional edge after ``hypothesis``: exploit or report.

    V10 P1-3: renamed from ``route_after_recon`` — the old name was a
    leftover from V3.5 when this router sat after the recon node. It
    has sat after ``hypothesis`` since V6.1, but the name was never
    updated, making the graph construction code misleading to read.
    A backward-compat alias ``route_after_recon = route_after_hypothesis``
    is kept below so any external callers / tests that imported the
    old name continue to work.

    V10 P0-B FIX: the previous version gated on ``state["findings"]``
    emptiness under ``skip_recon=True``. But ``hypothesis_node`` emits
    ``Hypothesis`` objects (V7 Phase 1 migration), NOT ``Finding``
    objects — so under ``skip_recon=True`` with path-classified
    hypotheses (e.g. /vulnerabilities/sqli/), the router short-
    circuited to ``NODE_REPORTER`` before the Strategist could
    promote any hypothesis to a Finding. Live operator symptom:
    skip_recon=True + path hypotheses → immediate Report + Persisted 0,
    no strategist/payload_generator/validator run.

    Fix: gate on OPEN HYPOTHESES (``state["hypotheses"]`` non-empty
    with status ``UNEXPLORED``) instead of findings emptiness. Any
    open hypothesis means the Strategist (sitting downstream of
    NODE_ACCESS_CONTROL → NODE_API_TESTING → NODE_BUSINESS_LOGIC_FUZZER
    → NODE_REQUEST_SMUGGLING → NODE_STRATEGIST) still has work to do.
    The Strategist's ``deterministic_match=True`` bypass (set by
    ``hypothesis_node`` on every path-classified hypothesis) already
    allows promotion without nuclei evidence — no strategist change
    needed.

    V6.1: If ``skip_recon`` is True, bypass the recon/crawler nodes
    entirely and go straight to hypothesis. The hypothesis_node uses
    the target URL as the sole endpoint.

    V7 Sprint 2: The routing goes through the deep-probing agents
    (access_control, api_testing, business_logic_fuzzer,
    request_smuggling) before reaching payload_generator. These agents
    may discover additional findings that weren't in the hypothesis
    pass, so they run even when the hypothesis found nothing
    actionable — they might find something the hypothesis missed.
    """
    # V10 P0-B: check for open hypotheses (UNEXPLORED status). The
    # hypothesis_node emits Hypothesis objects with status=UNEXPLORED
    # by default (models/hypothesis.py). The Strategist promotes them
    # to Findings; the router must NOT short-circuit past the
    # Strategist when open hypotheses exist.
    try:
        from webpent.models.hypothesis import HypothesisStatus
        unexplored = (
            HypothesisStatus.UNEXPLORED.value
            if hasattr(HypothesisStatus, "UNEXPLORED")
            else "unexplored"
        )
    except Exception:
        unexplored = "unexplored"

    from webpent.state.reducers import model_get
    hypotheses = state.get("hypotheses") or []
    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get instead of getattr so
    # dict-shaped hypotheses (after checkpoint round-trip) are handled
    # correctly — getattr(dict, "status", None) returns None (silent
    # degradation); model_get(dict, "status") returns the actual value.
    has_open_hypotheses = any(
        model_get(h, "status") == unexplored for h in hypotheses
    )

    # V6.1: Phase skipping — bypass recon + crawler.
    if state.get("skip_recon"):
        findings: list[Finding] = list(state.get("findings") or [])
        # V10 P0-B: route to access_control (which leads to strategist)
        # when EITHER findings OR open hypotheses exist. The previous
        # ``if not findings: return NODE_REPORTER`` gate dropped the
        # entire exploit chain when only hypotheses existed.
        if not findings and not has_open_hypotheses:
            # Genuine no-op fast path: operator requested skip_recon
            # AND there are no findings AND no open hypotheses. This
            # is the only case we short-circuit to reporter.
            return NODE_REPORTER
        # Findings OR open hypotheses exist — run the deep probes +
        # strategist so hypotheses get promoted to findings.
        return NODE_ACCESS_CONTROL
    # Normal path: always run the deep-probing agents. They may find
    # vulnerabilities the hypothesis missed (IDOR, GraphQL, race
    # conditions, request smuggling).
    return NODE_ACCESS_CONTROL


# V10 P1-3: backward-compat alias. Any code (or test) that imported
# ``route_after_recon`` continues to work; new code should use the
# renamed ``route_after_hypothesis``.
route_after_recon = route_after_hypothesis


def route_after_chainer(state: PentestState) -> str:
    """Conditional edge after ``exploit_chainer``: re-enter the exploit
    loop for new chained candidates, or proceed straight to
    post-exploitation if none were proposed.

    V7 "Apex Predator": exploit_chainer never executes anything itself
    (see its module docstring) — it only appends Pending findings
    tagged ``tool_name="exploit_chainer"``. If any exist, route back
    through NODE_PAYLOAD_GENERATOR so they get the exact same
    execution_sandbox (HITL-gated) -> validator -> devils_advocate
    treatment as every other finding — there is no shortcut path for
    chained candidates. If none were proposed this pass, proceed
    directly to post_exploitation as before this node existed.
    """
    findings: list[Finding] = list(state.get("findings") or [])
    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get for dict-safety.
    from webpent.state.reducers import model_get
    has_new_chain_candidates = any(
        model_get(f, "tool_name") == "exploit_chainer"
        and model_get(f, "confidence_level") == "Pending"
        for f in findings
    )
    return NODE_PAYLOAD_GENERATOR if has_new_chain_candidates else NODE_POST_EXPLOITATION


def route_after_rabbit_hole(state: PentestState) -> str:
    """Conditional edge after ``rabbit_hole``: bounded loop-back to
    Strategist, or fall through to cvss_engine.

    V8 P0 A2: closes the loop that the V7 graph left one-directional.
    When Rabbit Hole emits NEW RABBIT_HOLE-origin hypotheses (status
    UNEXPLORED — i.e. not yet promoted/abandoned by a prior Strategist
    pass), and the loop-back counter has not exceeded
    ``RabbitHolePolicy.max_loop_back_iterations``, route back to the
    Strategist so it can promote/abandon them. Otherwise fall through
    to cvss_engine (the V7 default behaviour).

    Bounded by:
      1. ``RabbitHolePolicy.max_loop_back_iterations`` (default 1, max 3)
         — the policy-level cap.
      2. ``state["rabbit_hole_loop_back_count"]`` — the runtime counter
         the Strategist increments on every re-entry pass.
      3. The presence of NEW RABBIT_HOLE-origin UNEXPLORED hypotheses
         — if all of them have already been decided (PROMOTED /
         ABANDONED), there is nothing for the Strategist to do, so
         we fall through.

    Pure deterministic routing — no LLM. The router does NOT mutate
    state (LangGraph conditional-edge functions must be pure); the
    counter is incremented INSIDE the Strategist node itself.
    """
    # Local imports to keep the module-import surface minimal.
    try:
        from webpent.config.policies import RabbitHolePolicy
        from webpent.models.hypothesis import HypothesisOrigin, HypothesisStatus
        from webpent.state.reducers import model_get
    except Exception:
        # If imports fail, fail-safe to the V7 default (no loop-back).
        return NODE_CVSS_ENGINE

    # Cap check.
    try:
        policy = RabbitHolePolicy()
    except Exception:
        return NODE_CVSS_ENGINE
    max_iters = getattr(policy, "max_loop_back_iterations", 0)
    current_count = int(state.get("rabbit_hole_loop_back_count") or 0)
    if max_iters <= 0 or current_count >= max_iters:
        return NODE_CVSS_ENGINE

    # New-hypotheses check: are there any RABBIT_HOLE-origin hypotheses
    # still in the UNEXPLORED status? (INVESTIGATING would also count,
    # but Rabbit Hole always emits UNEXPLORED.)
    hypotheses = state.get("hypotheses") or []
    rabbit_hole_origin = (HypothesisOrigin.RABBIT_HOLE.value
                          if hasattr(HypothesisOrigin, "RABBIT_HOLE")
                          else "rabbit_hole")
    unexplored = (HypothesisStatus.UNEXPLORED.value
                  if hasattr(HypothesisStatus, "UNEXPLORED")
                  else "unexplored")
    has_new = any(
        model_get(h, "origin") == rabbit_hole_origin
        and model_get(h, "status") == unexplored
        for h in hypotheses
    )
    if has_new:
        logger.info(
            "Rabbit Hole -> Strategist loop-back: re-entry %d/%d "
            "(new RABBIT_HOLE-origin hypotheses present).",
            current_count + 1, max_iters,
        )
        return NODE_STRATEGIST
    return NODE_CVSS_ENGINE


def route_after_validator(state: PentestState) -> str:
    """Conditional edge after ``validator``: optimize or debunk.

    V5 Sprint 10: The validator's conditional edge now routes to either
    NODE_PAYLOAD_OPTIMIZER (retry unconfirmed findings) or
    NODE_DEVILS_ADVOCATE (proceed to the Devil's Advocate debunking
    pass). The Devil's Advocate node then feeds directly into
    NODE_CVSS_ENGINE.
    """
    findings: list[Finding] = list(state.get("findings") or [])
    payloads_to_test: dict[str, list[str]] = dict(state.get("payloads_to_test") or {})
    retries: dict[str, int] = dict(state.get("optimization_retries") or {})

    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get for dict-safety so
    # findings loaded from a checkpoint (plain dicts after SqliteSaver
    # JSON round-trip) don't crash with AttributeError.
    from webpent.state.reducers import model_get
    for finding in findings:
        if not _meets_severity_threshold(finding):
            continue
        if not _is_exploitable(finding):
            continue
        if model_get(finding, "confidence") == Confidence.CONFIRMED.value:
            continue
        # A missing validator/tool is a terminal coverage limitation for this
        # bounded engagement. Retrying payloads cannot create evidence, so
        # fail closed and leave the candidate explicitly for human review.
        confidence_level = model_get(finding, "confidence_level", "")
        evidence = model_get(finding, "evidence") or {}
        if confidence_level == "Needs Human Review":
            continue
        if isinstance(evidence, dict) and (
            evidence.get("validation_unavailable")
            or evidence.get("tool_infra_failure")
        ):
            continue
        fid = str(model_get(finding, "id", ""))
        if not fid or fid not in payloads_to_test:
            continue
        # An empty payload set means no actionable retry exists (for example
        # offline mode, a browser-only validator without Playwright, or a
        # failed payload synthesis). Presence of the dict key alone must not
        # route the graph back into payload_optimizer forever.
        _queued_payloads = payloads_to_test.get(fid) or []
        if not _queued_payloads:
            continue
        # SQLi is confirmed by sqlmap's own payload engine. The synthetic
        # marker exists only to keep the execution-sandbox contract alive;
        # it is not an optimizer payload. Routing it through the optimizer
        # can never make progress and previously caused repeated sqlmap
        # invocations when a POST probe timed out or returned no marker.
        if (
            len(_queued_payloads) == 1
            and _queued_payloads[0] == "__SQLMAP_TOOL_DRIVEN__"
            and str(model_get(finding, "vuln_class", "")) == "sqli"
        ):
            continue
        current_retry = retries.get(fid, 0)
        if current_retry < _MAX_OPTIMIZATION_RETRIES:
            return NODE_PAYLOAD_OPTIMIZER
    # V5 Sprint 10: changed from NODE_CVSS_ENGINE to NODE_DEVILS_ADVOCATE
    return NODE_DEVILS_ADVOCATE


def route_after_devils_advocate(state: PentestState) -> str:
    """Route DA rejections through one bounded validator re-check.

    The Devil's Advocate is a hard gate for a fresh high-confidence
    rejection. The node marks those findings as Pending and records the
    revalidation trace; this router sends them back to the deterministic
    validator exactly once, then falls through to the normal chain.
    """
    revalidation_ids = state.get("devils_advocate_revalidation_ids") or []
    revalidation_count = int(state.get("devils_advocate_revalidation_count") or 0)
    gate_active = bool(state.get("devils_advocate_gate_active"))
    if gate_active and revalidation_ids and revalidation_count == 1:
        return NODE_VALIDATOR
    return NODE_EXPLOIT_CHAINER


def build_graph(checkpointer: Any = None, auto_approve: bool = False):
    """Construct and compile the WebPent engagement graph.

    Args:
        checkpointer: Optional LangGraph checkpointer for state persistence.
        auto_approve: If ``True``, compile without ``interrupt_before``
            so the graph runs to completion without pausing for human
            approval. Used for automated scanning pipelines.

    Returns:
        A compiled :class:`CompiledStateGraph`.
    """
    graph = StateGraph(PentestState)

    graph.add_node(NODE_PLANNER, planner_node)
    graph.add_node(NODE_AUTH, auth_node)
    graph.add_node(NODE_RECON, recon_node)
    graph.add_node(NODE_CRAWLER, crawler_node)
    graph.add_node(NODE_JAVASCRIPT_INTELLIGENCE, javascript_intelligence_node)
    graph.add_node(NODE_SUBDOMAIN_TAKEOVER, subdomain_takeover_node)
    graph.add_node(NODE_CLOUD_STORAGE, cloud_storage_node)
    graph.add_node(NODE_TARGET_UNDERSTANDING, target_understanding_node)
    graph.add_node(NODE_SCOPE_ENFORCER, scope_enforcer_node)
    graph.add_node(NODE_WAF_DETECTOR, waf_detector_node)
    graph.add_node(NODE_HYPOTHESIS, hypothesis_node)
    graph.add_node(NODE_PAYLOAD_GENERATOR, payload_generator_node)
    graph.add_node(NODE_EXECUTION_SANDBOX, execution_sandbox_node)
    graph.add_node(NODE_VALIDATOR, validator_node)
    graph.add_node(NODE_DEVILS_ADVOCATE, devils_advocate_node)
    graph.add_node(NODE_EXPLOIT_CHAINER, exploit_chainer_node)
    graph.add_node(NODE_POST_EXPLOITATION, post_exploitation_node)
    # V7 Cognitive Upgrade Phase 7: Rabbit Hole node — scans the Mental
    # Model for followable artifacts and emits new Hypotheses that
    # re-enter the existing payload_generator pipeline.
    graph.add_node(NODE_RABBIT_HOLE, rabbit_hole_node)
    # V7 Cognitive Upgrade Section 4: Strategist — promotion checkpoint.
    graph.add_node(NODE_STRATEGIST, strategist_node)
    graph.add_node(NODE_PAYLOAD_OPTIMIZER, payload_optimizer_node)
    graph.add_node(NODE_CVSS_ENGINE, cvss_node)
    graph.add_node(NODE_BUSINESS_IMPACT, business_impact_node)
    graph.add_node(NODE_CROSS_REASONING, cross_reasoning_node)
    graph.add_node(NODE_EXECUTIVE_SUMMARY, executive_summary_node)
    report_node = (
        reporter_node_bug_bounty
        if getattr(get_settings(), "enable_bug_bounty_reporter", False)
        else reporter_node
    )
    graph.add_node(NODE_REPORTER, report_node)
    graph.add_node(NODE_REFLECTION, reflection_node)

    # V7 Sprint 2: Register the new vulnerability-coverage agents.
    # These run as a "deep probing" phase between hypothesis and
    # payload_generator. Each agent adds findings to the state, which
    # the rest of the pipeline (validator → devils_advocate → cvss →
    # reporter) processes alongside the hypothesis-generated findings.
    graph.add_node(NODE_ACCESS_CONTROL, access_control_node)
    graph.add_node(NODE_API_TESTING, api_testing_node)
    graph.add_node(NODE_BUSINESS_LOGIC_FUZZER, business_logic_fuzzer_node)
    graph.add_node(NODE_REQUEST_SMUGGLING, request_smuggling_node)
    graph.add_node(NODE_DISCLOSED_REPORT_INTEL, disclosed_report_intel_node)
    graph.add_node(NODE_SMART_CAMPAIGNS, smart_campaigns_node)
    graph.add_node(NODE_SMART_CAMPAIGNS_EXECUTION, smart_campaigns_execution_node)
    graph.add_node(NODE_AUTONOMOUS_CONTROLLER, autonomous_controller_node)
    if _attack_graph_enabled():
        graph.add_node(NODE_ATTACK_GRAPH, attack_graph_node)

    # V3.5: CRAWLER -> SCOPE_ENFORCER -> WAF_DETECTOR
    # V6.1: Conditional edge from AUTH — if skip_recon, bypass to HYPOTHESIS.
    graph.add_edge(START, NODE_PLANNER)
    graph.add_edge(NODE_PLANNER, NODE_AUTH)

    # V6.1: Conditional routing after AUTH — skip recon if requested.
    graph.add_conditional_edges(
        NODE_AUTH, route_after_auth,
        {
            NODE_RECON: NODE_RECON,
            NODE_TARGET_UNDERSTANDING: NODE_TARGET_UNDERSTANDING,
            NODE_HYPOTHESIS: NODE_HYPOTHESIS,
        },
    )

    graph.add_edge(NODE_RECON, NODE_CRAWLER)
    graph.add_conditional_edges(
        NODE_CRAWLER,
        route_after_crawler,
        {
            NODE_JAVASCRIPT_INTELLIGENCE: NODE_JAVASCRIPT_INTELLIGENCE,
            NODE_SUBDOMAIN_TAKEOVER: NODE_SUBDOMAIN_TAKEOVER,
        },
    )
    graph.add_edge(NODE_JAVASCRIPT_INTELLIGENCE, NODE_SUBDOMAIN_TAKEOVER)
    graph.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE)
    graph.add_conditional_edges(
        NODE_CLOUD_STORAGE,
        route_after_infrastructure,
        {
            NODE_TARGET_UNDERSTANDING: NODE_TARGET_UNDERSTANDING,
            NODE_SCOPE_ENFORCER: NODE_SCOPE_ENFORCER,
        },
    )
    graph.add_edge(NODE_TARGET_UNDERSTANDING, NODE_SCOPE_ENFORCER)
    graph.add_edge(NODE_SCOPE_ENFORCER, NODE_WAF_DETECTOR)
    graph.add_edge(NODE_WAF_DETECTOR, NODE_HYPOTHESIS)

    graph.add_conditional_edges(
        # V10 P1-3: renamed route_after_recon -> route_after_hypothesis
        # (the router sits after NODE_HYPOTHESIS, not NODE_RECON). The
        # backward-compat alias is kept above for external callers.
        NODE_HYPOTHESIS, route_after_hypothesis,
        {NODE_ACCESS_CONTROL: NODE_ACCESS_CONTROL, NODE_REPORTER: NODE_REPORTER},
    )

    # V7 Sprint 2: Deep-probing agent chain.
    # access_control -> api_testing -> business_logic_fuzzer -> request_smuggling
    # -> strategist -> payload_generator
    # Each agent adds findings to the state. After all 4 agents have
    # run, the Strategist (V7 Section 4) promotes high-scoring
    # hypotheses to Findings, then payload_generator picks up all
    # actionable findings (both from the hypothesis and from the deep
    # probes and from Strategist promotions).
    graph.add_edge(NODE_ACCESS_CONTROL, NODE_API_TESTING)
    graph.add_edge(NODE_API_TESTING, NODE_BUSINESS_LOGIC_FUZZER)
    graph.add_edge(NODE_BUSINESS_LOGIC_FUZZER, NODE_REQUEST_SMUGGLING)
    # V7 Cognitive Upgrade Section 4: Strategist promotion checkpoint.
    # Runs after all discovery nodes, before payload_generator. Promotes
    # high-scoring hypotheses to Findings (deterministic score >= threshold).
    # The promoted Findings enter state["findings"] with
    # confidence_level="Pending" — exactly what payload_generator expects.
    graph.add_edge(NODE_REQUEST_SMUGGLING, NODE_DISCLOSED_REPORT_INTEL)
    if _attack_graph_enabled():
        graph.add_conditional_edges(
            NODE_DISCLOSED_REPORT_INTEL,
            route_after_disclosed_report_intel,
            {
                NODE_ATTACK_GRAPH: NODE_ATTACK_GRAPH,
                NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
                NODE_STRATEGIST: NODE_STRATEGIST,
            },
        )
        graph.add_conditional_edges(
            NODE_ATTACK_GRAPH,
            route_after_attack_graph,
            {
                NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
                NODE_STRATEGIST: NODE_STRATEGIST,
            },
        )
    else:
        graph.add_conditional_edges(
            NODE_DISCLOSED_REPORT_INTEL,
            route_after_disclosed_report_intel,
            {
                NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
                NODE_STRATEGIST: NODE_STRATEGIST,
            },
        )
    graph.add_edge(NODE_SMART_CAMPAIGNS, NODE_SMART_CAMPAIGNS_EXECUTION)
    graph.add_conditional_edges(
        NODE_SMART_CAMPAIGNS_EXECUTION,
        route_after_smart_campaigns_execution,
        {
            NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
            NODE_AUTONOMOUS_CONTROLLER: NODE_AUTONOMOUS_CONTROLLER,
            NODE_STRATEGIST: NODE_STRATEGIST,
        },
    )
    graph.add_edge(NODE_AUTONOMOUS_CONTROLLER, NODE_STRATEGIST)
    graph.add_edge(NODE_STRATEGIST, NODE_PAYLOAD_GENERATOR)

    graph.add_edge(NODE_PAYLOAD_GENERATOR, NODE_EXECUTION_SANDBOX)
    graph.add_edge(NODE_EXECUTION_SANDBOX, NODE_VALIDATOR)

    # V5 Sprint 10: Insert Devil's Advocate between validator and the
    # optimize/score conditional. The validator's conditional edge now
    # routes to either PAYLOAD_OPTIMIZER (retry) or DEVILS_ADVOCATE
    # (proceed to debunking). Devil's Advocate then feeds into CVSS.
    graph.add_conditional_edges(
        NODE_VALIDATOR, route_after_validator,
        {
            NODE_PAYLOAD_OPTIMIZER: NODE_PAYLOAD_OPTIMIZER,
            NODE_DEVILS_ADVOCATE: NODE_DEVILS_ADVOCATE,
        },
    )

    graph.add_edge(NODE_PAYLOAD_OPTIMIZER, NODE_EXECUTION_SANDBOX)

    # Phase 5.2: a fresh DA rejection is a hard gate and re-enters the
    # deterministic validator once; accepted/second-pass outcomes continue.
    graph.add_conditional_edges(
        NODE_DEVILS_ADVOCATE,
        route_after_devils_advocate,
        {
            NODE_VALIDATOR: NODE_VALIDATOR,
            NODE_EXPLOIT_CHAINER: NODE_EXPLOIT_CHAINER,
        },
    )
    graph.add_conditional_edges(
        NODE_EXPLOIT_CHAINER, route_after_chainer,
        {
            NODE_PAYLOAD_GENERATOR: NODE_PAYLOAD_GENERATOR,
            NODE_POST_EXPLOITATION: NODE_POST_EXPLOITATION,
        },
    )
    graph.add_edge(NODE_POST_EXPLOITATION, NODE_RABBIT_HOLE)
    # V7 Cognitive Upgrade Phase 7: Rabbit Hole emits new Hypotheses
    # (origin=RABBIT_HOLE) into the hypothesis pool.
    #
    # V8 P0 A2: BOUNDED LOOP-BACK to Strategist. Replaces the V7
    # one-directional edge `rabbit_hole -> cvss_engine` with a
    # conditional edge `rabbit_hole -> {strategist | cvss_engine}`.
    # When RABBIT_HOLE-origin hypotheses are present in state AND the
    # loop-back counter has not exceeded
    # RabbitHolePolicy.max_loop_back_iterations (default 1, max 3),
    # the graph routes back to the Strategist so it can promote the
    # new hypotheses to Findings. The Strategist on re-entry filters
    # to RABBIT_HOLE-origin hypotheses only — heuristic and cross-
    # reasons hypotheses already decided in the first pass are NOT
    # re-processed.
    #
    # The bounded loop-back is the closed loop the V7 plan called out
    # as "the Strategist's responsibility (Section 4), which is a
    # recurring decision function, not a single graph node." Phase A2
    # finally wires it: a Rabbit Hole hypothesis CAN now become a
    # Finding in the same engagement, traceable via hypothesis_id +
    # Decision Log (the Strategist's promotion entry sets branch_id
    # = str(hypothesis.id) on re-entry).
    #
    # HITL safety is inherited: any Finding promoted on re-entry
    # flows through NODE_PAYLOAD_GENERATOR -> NODE_EXECUTION_SANDBOX,
    # which is still gated by interrupt_before when auto_approve=False.
    # The loop-back does NOT add a new interrupt — it re-uses the
    # existing one.
    graph.add_conditional_edges(
        NODE_RABBIT_HOLE, route_after_rabbit_hole,
        {
            NODE_STRATEGIST: NODE_STRATEGIST,
            NODE_CVSS_ENGINE: NODE_CVSS_ENGINE,
        },
    )

    graph.add_edge(NODE_CVSS_ENGINE, NODE_BUSINESS_IMPACT)
    graph.add_edge(NODE_BUSINESS_IMPACT, NODE_CROSS_REASONING)
    # V5 Sprint 11: Executive Summary node runs after cross-reasoning
    # and before the reporter, so the reporter can embed the C-Suite
    # summary + risk score in the final report.
    graph.add_edge(NODE_CROSS_REASONING, NODE_EXECUTIVE_SUMMARY)
    graph.add_edge(NODE_EXECUTIVE_SUMMARY, NODE_REPORTER)

    graph.add_edge(NODE_REPORTER, NODE_REFLECTION)
    graph.add_edge(NODE_REFLECTION, END)

    if auto_approve:
        compiled = graph.compile(checkpointer=checkpointer)
        logger.info("Graph compiled with auto_approve=True (no HITL interrupt)")
    else:
        compiled = graph.compile(
            checkpointer=checkpointer,
            interrupt_before=[NODE_EXECUTION_SANDBOX],
        )
        logger.info("Graph compiled with HITL interrupt before %s", NODE_EXECUTION_SANDBOX)

    return compiled
