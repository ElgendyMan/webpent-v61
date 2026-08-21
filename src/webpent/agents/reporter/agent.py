# src/webpent/agents/reporter/agent.py
"""webpent.agents.reporter.agent

LangGraph node that aggregates all findings into a professional report
and persists it to disk.

V3 Phase 5 upgrades the reporter to generate both Markdown and HTML
reports. The HTML report is rendered from a Jinja2 template.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.api.scan_registry import get_thread_ids_by_engagement_id
from webpent.config.settings import get_settings
from webpent.memory.db import get_db_manager
from webpent.models.findings import Finding, Severity
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.shared.finding_aggregation import aggregate_findings
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger
from webpent.shared.report_quality import evaluate_report_quality
from webpent.state.reducers import model_get
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_REPORT_MD_FILENAME = "report.md"
_REPORT_HTML_FILENAME = "report.html"
_TEMPLATE_PATH = Path(__file__).parent.parent.parent / "templates" / "reports" / "html.j2"

_SYSTEM_PROMPT = (
    "You are a Senior Security Consultant writing an executive summary "
    "for a penetration test engagement. Use clear, professional language "
    "suitable for both technical and executive audiences. Output Markdown "
    "only — no preamble, no code fences."
)

_HUMAN_TEMPLATE_WITH_FINDINGS = (
    "Target: {target}\n"
    "Total findings: {count}\n\n"
    "Findings table (Markdown):\n\n{table}\n\n"
    "Write a concise executive summary (3-5 paragraphs) covering:\n"
    "1. Overall security posture.\n"
    "2. Most critical risks and their business impact.\n"
    "3. Recommended remediation priorities.\n"
)

_HUMAN_TEMPLATE_NO_FINDINGS = (
    "Target: {target}\n"
    "Total findings: 0\n\n"
    "Write a brief executive summary (2-3 paragraphs) noting that no "
    "vulnerabilities were identified during the engagement and "
    "recommending continued monitoring."
)

_FALLBACK_SUMMARY = (
    "An automated executive summary could not be generated because all "
    "configured LLM providers were unavailable. Refer to the structured "
    "findings table below for the raw results of the engagement. "
    "Manual review and narrative composition are recommended."
)

# V7 Sprint 3.3: Bug-bounty report format.
# Most bug bounty platforms (HackerOne, Bugcrowd) expect a specific
# report structure: Summary, Steps to Reproduce, Impact, Suggested
# Fix, and Supporting Material. This is distinct from the enterprise
# report format (which includes compliance mapping, CVSS vectors,
# and executive summaries). The bug-bounty format is more concise
# and action-oriented — it's written for the triage team, not for
# executives.
_BUG_BOUNTY_SYSTEM_PROMPT = (
    "You are a Bug Bounty Report Writer. For each vulnerability, "
    "produce a structured bug-bounty report with the following "
    "sections: Summary, Steps to Reproduce, Impact, Suggested Fix, "
    "and Supporting Material. Use clear, concise language suitable "
    "for a bug bounty triage team. Output Markdown only — no preamble, "
    "no code fences. Each finding should be a separate section "
    "starting with '## [Severity] Finding Title'."
)

_BUG_BOUNTY_HUMAN_TEMPLATE = (
    "Target: {target}\n"
    "Total findings: {count}\n\n"
    "Findings (Markdown table):\n\n{table}\n\n"
    "For EACH finding, write a bug-bounty report section with:\n"
    "1. **Summary** — 1-2 sentence description of the vulnerability.\n"
    "2. **Steps to Reproduce** — numbered steps to trigger the vuln.\n"
    "3. **Impact** — what an attacker can achieve.\n"
    "4. **Suggested Fix** — concrete remediation advice.\n"
    "5. **Supporting Material** — evidence (request/response snippets, "
    "screenshots references, CVSS scores).\n"
)

_REPORT_BUG_BOUNTY_MD_FILENAME = "bug_bounty_report.md"


def _findings_with_proof_bundles(
    findings: Iterable[Any],
    proof_bundles: Iterable[Any] | None,
) -> list[Any]:
    """Attach matching state-level proof bundles to report-only finding views."""
    bundle_by_ref: dict[str, dict[str, Any]] = {}
    for raw_bundle in proof_bundles or ():
        if not isinstance(raw_bundle, Mapping):
            continue
        bundle_ref = str(raw_bundle.get("finding_id") or "").strip()
        if bundle_ref:
            bundle_by_ref[bundle_ref] = dict(raw_bundle)
    views: list[Any] = []
    for finding in findings:
        finding_id = str(model_get(finding, "id", "") or "").strip()
        hypothesis_id = str(model_get(finding, "hypothesis_id", "") or "").strip()
        bundle = bundle_by_ref.get(finding_id) or bundle_by_ref.get(hypothesis_id)
        if bundle is None:
            views.append(finding)
            continue
        if isinstance(finding, Mapping):
            view = dict(finding)
        elif hasattr(finding, "model_dump"):
            view = finding.model_dump(mode="json")
        else:
            views.append(finding)
            continue
        view["proof_bundle"] = bundle
        views.append(view)
    return views


def _compose_bug_bounty_markdown(
    target_url: str,
    findings: list[Finding],
    llm_generated_sections: str,
    crawled_data: dict[str, Any] | None = None,
) -> str:
    """V7 Sprint 3.3: Compose a bug-bounty-ready Markdown report.

    Structure (per HackerOne/Bugcrowd conventions):
      * Header: target, date, total findings
      * Per-finding sections with: Summary, Steps to Reproduce,
        Impact, Suggested Fix, Supporting Material
      * Appendix: JS secrets discovered (if any)
    """
    lines: list[str] = [
        "# Bug Bounty Report", "",
        f"**Target:** {target_url}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {len(findings)}",
        "",
    ]

    # If the LLM generated per-finding sections, include them.
    if llm_generated_sections.strip():
        lines.extend(["## Findings", "", llm_generated_sections.strip(), ""])
    else:
        # Fallback: render a structured table if the LLM call failed.
        lines.extend(["## Findings", "", _render_findings_table(findings), ""])

    # Appendix: JS secrets discovered during crawling.
    if crawled_data and crawled_data.get("js_secrets"):
        secrets = crawled_data["js_secrets"]
        lines.extend([
            "## Appendix: Exposed Secrets in JavaScript", "",
            "The following secrets were discovered in the target's "
            "client-side JavaScript files during the crawl phase:", "",
            "| Type | Value (truncated) | Source |",
            "|------|-------------------|--------|",
        ])
        for s in secrets:
            lines.append(
                f"| {s.get('type', 'Unknown')} | "
                f"{s.get('value', '—')} | "
                f"{s.get('source', '—')} |"
            )
        lines.append("")

    # Appendix: Hidden parameters discovered.
    if crawled_data and crawled_data.get("hidden_parameters"):
        params = crawled_data["hidden_parameters"]
        lines.extend([
            "## Appendix: Hidden Parameters Discovered", "",
            "The following undocumented parameters were discovered via "
            "parameter mining (Arjun-style probing):", "",
            "| Parameter | URL | Evidence |",
            "|-----------|-----|----------|",
        ])
        for p in params:
            lines.append(
                f"| {p.get('param', '—')} | "
                f"{p.get('url', '—')} | "
                f"{p.get('evidence', '—')} |"
            )
        lines.append("")

    return "\n".join(lines)


def _sanitize_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_findings_table(findings: Iterable[Finding]) -> str:
    header = (
        "| # | Title | Severity | CVSS | Confidence | Business Impact | Reasoning | URL |\n"
        "|---|-------|----------|------|------------|-----------------|-----------|-----|\n"
    )
    rows: list[str] = []
    for idx, finding in enumerate(findings, start=1):
        title = _sanitize_cell(str(model_get(finding, "title", "") or ""))
        severity = _sanitize_cell(str(model_get(finding, "severity", "") or ""))
        cvss = _sanitize_cell(str(model_get(finding, "cvss_score") or "—"))
        conf_level = _sanitize_cell(
            str(model_get(finding, "confidence_level", "Pending") or "Pending")
        )
        impact = _sanitize_cell(str(model_get(finding, "business_impact") or "—"))
        # V5 Sprint 5: Expose the audit-trail reasoning in the report.
        # Truncate long justifications so the Markdown table stays readable.
        reasoning_raw = str(model_get(finding, "reasoning", "") or "")
        reasoning = _sanitize_cell(reasoning_raw[:300]) if reasoning_raw else "—"
        url = _sanitize_cell(str(model_get(finding, "url", "") or ""))
        rows.append(
            f"| {idx} | {title} | {severity} | {cvss} | {conf_level} | "
            f"{impact} | {reasoning} | {url} |"
        )
    return header + "\n".join(rows)


def _build_human_prompt(target_url: str, findings: list[Finding]) -> str:
    if not findings:
        return safe_prompt_format(
            _HUMAN_TEMPLATE_NO_FINDINGS, target=target_url
        )
    return safe_prompt_format(
        _HUMAN_TEMPLATE_WITH_FINDINGS,
        target=target_url, count=len(findings),
        table=_render_findings_table(findings),
    )


def _compose_markdown(
    target_url: str,
    findings: list[Finding],
    executive_summary: str,
    decision_log: list[dict[str, Any]] | None = None,
) -> str:
    """Compose the legacy Markdown report.

    V8 P0 A3: now appends a ``## Decision Log`` appendix when
    ``decision_log`` is non-empty, so the legacy Markdown path also
    surfaces promotion / abandon / risk-gate decisions. Mirrors the
    HTML template's Decision Log section.
    """
    lines: list[str] = [
        "# WebPent Engagement Report", "",
        f"**Target:** {target_url}",
        f"**Total findings:** {len(findings)}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        "", "## Executive Summary", "", executive_summary.strip(), "",
    ]
    if findings:
        lines.extend(["## Findings", "", _render_findings_table(findings), ""])
    # V8 P0 A3: Decision Log appendix.
    if decision_log:
        lines.extend([
            "## Decision Log", "",
            "Every promotion, abandonment, scope check, and risk-gate "
            "decision the framework made during this engagement, in "
            "chronological order. `Rule Fired` is the deterministic "
            "rule that triggered the decision (never LLM free text).",
            "",
            "| # | Timestamp (UTC) | Type | Rule Fired | Outcome | Branch ID |",
            "|---|-----------------|------|------------|---------|-----------|",
        ])
        for i, entry in enumerate(decision_log, 1):
            ts = (entry.get("timestamp") or "")[:19] or "—"
            dtype = entry.get("decision_type") or "—"
            rule = (entry.get("rule_fired") or "—").replace("|", "\\|")
            outcome = (entry.get("outcome") or "—").replace("|", "\\|")
            branch = entry.get("branch_id") or "—"
            lines.append(
                f"| {i} | `{ts}` | `{dtype}` | {rule} | {outcome} | `{branch}` |"
            )
        lines.append("")
    return "\n".join(lines)


def _save_report(content: str, output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def _compute_stats(findings: list[Finding]) -> dict[str, int]:
    tool_confirmed = sum(
        1 for f in findings
        if model_get(f, "confidence_level", "") == "Tool-Confirmed"
    )
    critical = sum(
        1 for f in findings
        if str(model_get(f, "severity", "")).lower() == Severity.CRITICAL.value
    )
    high = sum(
        1 for f in findings
        if str(model_get(f, "severity", "")).lower() == Severity.HIGH.value
    )
    return {
        "confirmed_count": tool_confirmed,
        "critical_count": critical,
        "high_count": high,
    }


def _findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for f in findings:
        result.append({
            "title": str(model_get(f, "title", "") or ""),
            "severity": str(model_get(f, "severity", "") or ""),
            "confidence": str(model_get(f, "confidence", "") or ""),
            "confidence_level": model_get(f, "confidence_level", "Pending") or "Pending",
            "cvss_score": model_get(f, "cvss_score") or "",
            "business_impact": model_get(f, "business_impact") or "",
            # V5 Sprint 5: Expose reasoning for the audit trail section
            # in the HTML template. Empty string keeps the template
            # truthiness checks simple.
            "reasoning": model_get(f, "reasoning", "") or "",
            "url": str(model_get(f, "url", "") or ""),
        })
    return result


def _render_html_report(
    target_url: str, findings: list[Finding],
    executive_summary: str, hypotheses: list[str],
) -> str | None:
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.warning("Jinja2 is not installed — HTML report will not be generated.")
        return None

    template_dir = _TEMPLATE_PATH.parent
    template_name = _TEMPLATE_PATH.name

    if not _TEMPLATE_PATH.exists():
        logger.warning("HTML template not found at %s — skipping HTML report.", _TEMPLATE_PATH)
        return None

    try:
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template(template_name)
        stats = _compute_stats(findings)
        html = template.render(
            target_url=target_url, total_findings=len(findings),
            confirmed_count=stats["confirmed_count"],
            critical_count=stats["critical_count"],
            high_count=stats["high_count"],
            executive_summary=executive_summary,
            findings=_findings_to_dicts(findings),
            hypotheses=hypotheses,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )
        logger.info("HTML report rendered successfully")
        return html
    except Exception as exc:
        logger.warning("Failed to render HTML report: %s. Only Markdown will be saved.", exc)
        return None


def reporter_node(state: PentestState) -> dict:
    """LangGraph node implementing the reporting phase.

    V5 Sprint 11: Now reads ``executive_summary`` and ``risk_score``
    from graph state (populated by the executive_summary_node) and
    delegates multi-format export to ``webpent.reporter.export``.
    Falls back to the legacy LLM-generated summary if the
    executive_summary_node did not populate the field.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    # Reports are cumulative within one explicit engagement scope. The current
    # run may not be persisted until the worker returns, so merge historical
    # DB findings first and keep the current state as the authoritative input
    # for this run. Any registry/DB failure falls back to the current state.
    engagement_id = str(state.get("engagement_id") or "")
    client_id = str(state.get("client_id") or "")
    if engagement_id:
        try:
            sibling_threads = get_thread_ids_by_engagement_id(
                engagement_id,
                client_id=client_id,
            )
            historical = get_db_manager().get_findings_by_threads(sibling_threads)
            findings = aggregate_findings([*historical, *findings])
            ledger_findings = PersistentFindingLedger(
                get_settings().findings_ledger_path
            ).get(engagement_id)
            findings = aggregate_findings([*ledger_findings, *findings])
        except Exception as exc:
            logger.warning(
                "Cumulative report projection unavailable for engagement %s: %s",
                engagement_id,
                exc,
            )
    # V7 Cognitive Upgrade — Phase 1: state["hypotheses"] is now
    # list[Hypothesis] (atomic type migration). The reporter / export
    # pipeline / Jinja2 templates all expect list[str], so extract
    # .statement from each Hypothesis for the legacy rendering path.
    # The full Hypothesis objects remain in state for Dynamic
    # Prioritization / Decision Log / Rabbit Hole consumers.
    raw_hypotheses = list(state.get("hypotheses") or [])
    # V9 P0 B2 defense-in-depth: dedupe by hypothesis id (the
    # merge_hypotheses reducer already does this in state, but we
    # guard here too so a future regression in the reducer cannot
    # produce duplicate hypothesis text in the report).
    seen_hyp_ids: set = set()
    hypotheses: list[str] = []
    for h in raw_hypotheses:
        if isinstance(h, str):
            # Backward compat: legacy callers still passing strings.
            # Dedupe by the string itself.
            if h not in hypotheses:
                hypotheses.append(h)
        elif hasattr(h, "statement") or isinstance(h, dict):
            # V7 Hypothesis object or checkpoint-shaped dictionary — dedupe
            # by id and preserve its statement on resumed engagements.
            hid = model_get(h, "id")
            if hid is not None:
                if hid in seen_hyp_ids:
                    continue
                seen_hyp_ids.add(hid)
            statement = model_get(h, "statement", "")
            hypotheses.append(str(statement) if statement else str(h))
        else:
            s = str(h)
            if s not in hypotheses:
                hypotheses.append(s)

    # V5 Sprint 11: read the AI executive summary + risk score from
    # state (populated by executive_summary_node). Fall back to the
    # legacy LLM call if not present.
    executive_summary: str = state.get("executive_summary", "") or ""
    risk_score: str = state.get("risk_score", "Low") or "Low"

    target_url = str(model_get(target, "url", "") or "")
    settings = get_settings()
    proof_required = bool(getattr(settings, "smart_require_proof_bundle", False))
    report_findings = _findings_with_proof_bundles(
        findings,
        state.get("proof_bundles") or [],
    )
    quality_result = evaluate_report_quality(
        report_findings,
        require_proof_bundle=proof_required,
    )
    quality_dump = quality_result.model_dump(mode="json")

    logger.info(
        "Reporter phase starting for target=%s with %d finding(s) "
        "(risk=%s, summary_from_state=%s)",
        target_url, len(findings), risk_score, bool(executive_summary),
    )

    # Strict mode is opt-in. It fails closed before any LLM narrative is
    # generated, and returns only field names/statuses in the state audit.
    if (
        getattr(settings, "enable_report_quality_gate", False) or proof_required
    ) and not quality_result.ready:
        return {
            "messages": [AIMessage(content=(
                "Report quality gate blocked export: one or more findings "
                "lack required evidence contract fields. Review the "
                "report_quality_gate audit before retrying."
            ))],
            "report_quality_gate": quality_dump,
            "current_phase": "reporting",
        }

    # If the executive_summary_node did not populate the field, fall
    # back to the legacy LLM call.
    if not executive_summary:
        llm = try_get_llm(TaskType.ANALYSIS)
        human_prompt = _build_human_prompt(target_url, findings)
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            executive_summary = (
                response.content if isinstance(response.content, str)
                else str(response.content)
            )
        except Exception as exc:
            logger.error(
                "All LLM providers failed for reporter: %s. Using fallback summary.",
                exc,
            )
            executive_summary = _FALLBACK_SUMMARY

    decision_log: list[dict[str, Any]] = list(state.get("decision_log") or [])

    # V9 P0 [round-2 wiring audit]: resolve output_dir first and
    # guarded. export_all_formats() below needs this same output_dir
    # independently of whether the legacy Markdown path (next block)
    # succeeds, so this is split out rather than guarded together with
    # markdown composition — a Markdown-only failure must not also
    # block the JSON/HTML/PDF export from being attempted.
    try:
        output_dir = get_settings().ensure_output_dir()
    except Exception as exc:
        # Previously unguarded: a permissions/disk-full error here
        # used to crash reporter_node (the graph's LAST node)
        # uncaught. No report file (Markdown, JSON, HTML, or PDF) can
        # be written without a usable output directory, so this is
        # the one sub-case where returning early is correct rather
        # than attempting the multi-format export below.
        logger.error(
            "Could not create/access the report output directory "
            "(%s). No report file can be written this run. Findings "
            "remain persisted in the database (incremental "
            "persistence) and are retrievable via the API/DB once "
            "the output path issue is resolved.",
            exc,
        )
        return {
            "messages": [AIMessage(content=(
                f"Report generation failed: output directory "
                f"unavailable ({exc}). Findings remain persisted in "
                "the database."
            ))],
            "current_phase": "reporting",
        }

    # Legacy Markdown report (preserved for backward compat).
    # V8 P0 A3: pass the Decision Log so the legacy Markdown path also
    # surfaces promotion / abandon / risk-gate decisions. (The HTML
    # template gets it via export_all_formats below.)
    # V10 P3-3 FIX (a): initialise md_path=None before the try block so
    # the except handler below never sees an undefined name (the
    # previous code only assigned md_path inside the try, so a
    # _compose_markdown failure followed by a _render_html_report
    # fallback failure logged md_path as an unbound local).
    selected_formats = state.get("report_formats")
    markdown_requested = (
        selected_formats is None
        or "all" in selected_formats
        or "md" in selected_formats
    )
    md_path: str | None = None
    markdown_failed = False
    try:
        if markdown_requested:
            markdown = _compose_markdown(
                target_url, findings, executive_summary, decision_log=decision_log
            )
            md_path = _save_report(markdown, output_dir, _REPORT_MD_FILENAME)
            logger.info("Markdown report written to %s", md_path)
    except Exception as exc:
        markdown_failed = True
        # V9 P0 [round-2 wiring audit]: previously unguarded — a
        # formatting error triggered by one malformed finding (e.g. an
        # unexpected None/type in a field _compose_markdown doesn't
        # defensively handle) used to crash the entire reporter_node
        # uncaught, sacrificing the JSON/HTML/PDF export below too
        # even though that export does not depend on the Markdown
        # path succeeding. Log and continue instead.
        logger.error(
            "Legacy Markdown report generation failed (%s) — "
            "continuing to JSON/HTML/PDF export, which does not "
            "depend on the Markdown path. Findings remain persisted "
            "in the database regardless.",
            exc,
        )

    html_requested = (
        selected_formats is None
        or "all" in selected_formats
        or "html" in selected_formats
    )

    # V5 Sprint 11: Multi-format export (JSON + HTML + PDF) with
    # cryptographic audit trail + compliance tags.
    # V7 Cognitive Upgrade — Phase 6: pass the Decision Log from state
    # so it's surfaced in the report's explainability appendix.
    # V10 P3-3 FIX (b): track export_ok so the final return message
    # can be downgraded to a WARNING when both Markdown composition
    # AND the multi-format export (incl. legacy HTML fallback) fail.
    export_ok = False
    try:
        from webpent.reporter.export import export_all_formats

        campaign_ledger = dict(state.get("campaign_ledger") or {})
        campaign_plan = state.get("campaign_plan")
        if isinstance(campaign_plan, dict):
            # Preserve the declarative planner output separately from the
            # projection-only smart coverage ledger.
            campaign_ledger["campaign_plan"] = campaign_plan
        campaign_ledger["coverage_projection"] = project_coverage_ledger(state)
        campaign_ledger["task_outcome_count"] = len(state.get("campaign_task_outcomes") or [])
        campaign_ledger["http_observation_count"] = len(state.get("smart_http_observations") or [])
        paths = export_all_formats(
            target_url=target_url,
            findings=report_findings,
            output_dir=output_dir,
            executive_summary=executive_summary,
            risk_score=risk_score,
            hypotheses=hypotheses,
            decision_log=decision_log,
            bac_observations=list(state.get("bac_observations") or []),
            bac_coverage_gaps=list(state.get("bac_coverage_gaps") or []),
            relational_evidence=list(state.get("relational_evidence") or []),
            subdomain_takeover_observations=list(
                state.get("subdomain_takeover_observations") or []
            ),
            subdomain_takeover_coverage_gaps=list(
                state.get("subdomain_takeover_coverage_gaps") or []
            ),
            cloud_storage_observations=list(state.get("cloud_storage_observations") or []),
            cloud_storage_coverage_gaps=list(state.get("cloud_storage_coverage_gaps") or []),
            jwt_deep_observations=list(state.get("jwt_deep_observations") or []),
            jwt_deep_coverage_gaps=list(state.get("jwt_deep_coverage_gaps") or []),
            disclosed_report_advisories=list(state.get("disclosed_report_advisories") or []),
            advisory_coverage_gaps=list(state.get("advisory_coverage_gaps") or []),
            strict_quality_gate=bool(getattr(settings, "enable_report_quality_gate", False)),
            require_proof_bundle=proof_required,
            coverage_ledger=dict(state.get("coverage_ledger") or {}),
            campaign_ledger=campaign_ledger,
            proof_observability=dict(state.get("proof_observability") or {}),
            authorization_matrix=dict(state.get("authorization_matrix") or {}),
            formats=list(selected_formats) if selected_formats else None,
        )
        export_ok = True
        rendered = ", ".join(
            f"{name}={path}" for name, path in paths.items() if path is not None
        ) or "none"
        logger.info("V5 Sprint 11 multi-format export complete: %s", rendered)
    except Exception as exc:
        logger.warning(
            "V5 Sprint 11 multi-format export failed (%s) — falling "
            "back to legacy HTML render.", exc,
        )
        # V9 P0 B10: guard the fallback path too — a bad UUID/datetime/None
        # in _render_html_report must NOT wipe the engagement's Markdown
        # report (already written above) or crash the graph. Respect an
        # explicit format selection: JSON-only/MD-only runs must not create
        # an unrequested HTML artifact.
        if html_requested:
            try:
                html = _render_html_report(target_url, findings, executive_summary, hypotheses)
                if html is not None:
                    html_path = _save_report(html, output_dir, _REPORT_HTML_FILENAME)
                    export_ok = True
                    logger.info("HTML report written to %s (legacy)", html_path)
            except Exception as fallback_exc:
                logger.error(
                    "Legacy HTML render also failed (%s) — Markdown report "
                    "at %s is the canonical output. Engagement findings are "
                    "still persisted in the DB; only the HTML rendering is lost.",
                    fallback_exc, md_path,
                )
        else:
            logger.error(
                "Selected report formats failed and no HTML fallback was requested; "
                "engagement findings remain persisted in the DB."
            )

    # V10 P3-3 FIX (b): previously this returned "Report generated
    # successfully." unconditionally — even when BOTH Markdown
    # composition and the multi-format export (incl. legacy HTML
    # fallback) raised exceptions. Downgrade to a WARNING in that case
    # so the operator is alerted that no report artifact was produced
    # (findings remain persisted in the DB regardless).
    if markdown_failed and not export_ok:
        return {
            "messages": [AIMessage(content=(
                "WARNING: report generation failed — both Markdown "
                "composition and the multi-format export raised "
                "exceptions. Findings remain persisted in the database "
                "but no report artifact was written. Check the logs "
                "for details."
            ))],
            "current_phase": "reporting",
        }

    return {
        "messages": [AIMessage(content="Report generated successfully.")],
        "report_quality_gate": quality_dump,
        "current_phase": "reporting",
    }


def reporter_node_bug_bounty(state: PentestState) -> dict:
    """V7 Sprint 3.3: Generate a bug-bounty-ready report.

    Produces a Markdown report with the HackerOne/Bugcrowd structure:
    Summary, Steps to Reproduce, Impact, Suggested Fix, Supporting
    Material. Also includes appendices for JS secrets and hidden
    parameters discovered during recon.

    This node reads the same state as the enterprise ``reporter_node``
    but produces a differently-structured output. It can be used as a
    drop-in replacement for ``reporter_node`` when the operator wants
    a bug-bounty-format report instead of an enterprise report.

    Usage (in graph/builder.py)::

        # To use bug-bounty format, replace reporter_node with
        # reporter_node_bug_bounty in the graph:
        graph.add_node(NODE_REPORTER, reporter_node_bug_bounty)
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}
    target_url = str(model_get(target, "url", "") or "")
    settings = get_settings()
    proof_required = bool(getattr(settings, "smart_require_proof_bundle", False))
    report_findings = _findings_with_proof_bundles(
        findings,
        state.get("proof_bundles") or [],
    )
    quality_result = evaluate_report_quality(
        report_findings,
        require_proof_bundle=proof_required,
    )
    quality_dump = quality_result.model_dump(mode="json")

    logger.info(
        "Bug-bounty reporter starting for target=%s with %d finding(s)",
        target_url, len(findings),
    )

    if (
        getattr(settings, "enable_report_quality_gate", False) or proof_required
    ) and not quality_result.ready:
        return {
            "messages": [AIMessage(content=(
                "Bug-bounty report blocked by the evidence quality gate. "
                "Review report_quality_gate and complete the missing "
                "contract fields before export."
            ))],
            "report_quality_gate": quality_dump,
            "current_phase": "reporting",
        }

    # Generate per-finding bug-bounty sections via the LLM.
    llm_generated_sections = ""
    if findings:
        llm = try_get_llm(TaskType.ANALYSIS)
        human_prompt = safe_prompt_format(
            _BUG_BOUNTY_HUMAN_TEMPLATE,
            target=target_url,
            count=len(findings),
            table=_render_findings_table(findings),
        )
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_BUG_BOUNTY_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            llm_generated_sections = (
                response.content if isinstance(response.content, str)
                else str(response.content)
            )
        except Exception as exc:
            logger.error(
                "LLM failed for bug-bounty report: %s. Using fallback table format.",
                exc,
            )
            llm_generated_sections = ""

    # Compose the bug-bounty Markdown report.
    markdown = _compose_bug_bounty_markdown(
        target_url, findings, llm_generated_sections, crawled_data,
    )

    output_dir = get_settings().ensure_output_dir()
    md_path = _save_report(markdown, output_dir, _REPORT_BUG_BOUNTY_MD_FILENAME)
    logger.info("Bug-bounty Markdown report written to %s", md_path)

    return {
        "messages": [AIMessage(
            content=f"Bug-bounty report generated successfully at {md_path}."
        )],
        "report_quality_gate": quality_dump,
        "current_phase": "reporting",
    }
