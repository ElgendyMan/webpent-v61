# src/webpent/reporter/export.py
"""webpent.reporter.export

V5 Sprint 11 — Multi-format reporting engine.

Exports the final state of findings to JSON, HTML (via Jinja2), and PDF
(via weasyprint if available, with a pdfkit fallback). Each format
includes the cryptographic audit trail (per-finding evidence hashes +
master report hash).

Public API::

    from webpent.reporter.export import (
        export_to_json,
        export_to_html,
        export_to_pdf,
        export_all_formats,
    )
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.models.evidence import redact_sensitive
from webpent.models.findings import Finding
from webpent.shared.report_quality import (
    enforce_report_quality,
    evaluate_report_quality,
    lifecycle_stage,
)
from webpent.state.reducers import model_get
from webpent.utils.compliance import tag_finding
from webpent.utils.crypto import (
    build_audit_trail,
    hash_evidence_bundle,
    hash_report,
)

logger = logging.getLogger(__name__)

_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "reports" / "report.html.j2"


def _finding_to_dict(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    """Convert a Finding or checkpoint-shaped dict to a JSON-safe dict.

    LangGraph checkpoint round-trips do not necessarily rehydrate Pydantic
    models.  Report generation must therefore accept both live ``Finding``
    instances and plain dictionaries without dropping compliance tags or
    crashing on attribute access.
    """
    existing_tags = model_get(finding, "compliance_tags") or []
    tags = existing_tags or tag_finding(finding)

    evidence_bundle = model_get(finding, "evidence_bundle")
    ev_hash = model_get(finding, "evidence_hash")
    if ev_hash is None and evidence_bundle is not None:
        try:
            ev_hash = hash_evidence_bundle(evidence_bundle)
        except Exception:
            ev_hash = None

    finding_id = model_get(finding, "id")
    created_at = model_get(finding, "created_at")
    if hasattr(created_at, "isoformat"):
        created_at_value = created_at.isoformat()
    else:
        created_at_value = str(created_at) if created_at is not None else ""

    hypothesis_id = model_get(finding, "hypothesis_id")
    return {
        "id": str(finding_id) if finding_id is not None else "",
        "title": model_get(finding, "title", "") or "",
        "severity": str(model_get(finding, "severity", "") or ""),
        "description": model_get(finding, "description", "") or "",
        "tool_name": model_get(finding, "tool_name", "") or "",
        "payload": model_get(finding, "payload"),
        "url": model_get(finding, "url", "") or "",
        "confidence": str(model_get(finding, "confidence", "") or ""),
        "confidence_level": model_get(finding, "confidence_level", "") or "",
        "cvss_score": model_get(finding, "cvss_score"),
        "business_impact": model_get(finding, "business_impact"),
        "vuln_class": model_get(finding, "vuln_class"),
        "reasoning": model_get(finding, "reasoning", "") or "",
        "canary_token": model_get(finding, "canary_token"),
        "compliance_tags": tags or [],
        "evidence_bundle": evidence_bundle,
        "evidence_hash": ev_hash,
        "proof_bundle": model_get(finding, "proof_bundle"),
        "created_at": created_at_value,
        # V7 Cognitive Upgrade — Phase 4: surface the new informational
        # fields so the audit trail (belief -> investigation -> finding)
        # is visible in the JSON export.
        "strategic_confidence_score": model_get(finding, "strategic_confidence_score"),
        "hypothesis_id": str(hypothesis_id) if hypothesis_id else None,
        "post_exploitation_data": model_get(finding, "post_exploitation_data"),
        # Phase 11: expose the normalized evidence lifecycle while retaining
        # all legacy categorical fields for backward-compatible consumers.
        "lifecycle_stage": lifecycle_stage(finding),
    }


def _redact_report_value(value: Any, key: str = "") -> Any:
    """Recursively apply the canonical evidence redaction contract."""
    clean, _ = redact_sensitive(value, key_hint=key)
    return clean


def build_report_data(
    target_url: str,
    findings: list[Finding],
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    bac_observations: list[dict[str, Any]] | None = None,
    bac_coverage_gaps: list[dict[str, Any]] | None = None,
    relational_evidence: list[dict[str, Any]] | None = None,
    subdomain_takeover_observations: list[dict[str, Any]] | None = None,
    subdomain_takeover_coverage_gaps: list[dict[str, Any]] | None = None,
    cloud_storage_observations: list[dict[str, Any]] | None = None,
    cloud_storage_coverage_gaps: list[dict[str, Any]] | None = None,
    jwt_deep_observations: list[dict[str, Any]] | None = None,
    jwt_deep_coverage_gaps: list[dict[str, Any]] | None = None,
    disclosed_report_advisories: list[dict[str, Any]] | None = None,
    advisory_coverage_gaps: list[dict[str, Any]] | None = None,
    strict_quality_gate: bool = False,
    require_proof_bundle: bool = False,
    coverage_ledger: dict[str, Any] | None = None,
    campaign_ledger: dict[str, Any] | None = None,
    proof_observability: dict[str, Any] | None = None,
    authorization_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical report data structure used by all export formats.

    V5 Sprint 11: This is the single source of truth for the report
    content. JSON, HTML, and PDF exports all consume this dict so the
    cryptographic audit trail is consistent across formats.

    V7 Cognitive Upgrade — Phase 6: ``decision_log`` is surfaced in the
    report as an explainability appendix, per the plan: "surfaced in the
    final report as an explainability appendix — a natural extension of
    the project's existing audit-trail ethos."
    """
    findings_dicts = [_redact_report_value(_finding_to_dict(f)) for f in findings]
    quality_result = (
        enforce_report_quality(findings, require_proof_bundle=require_proof_bundle)
        if strict_quality_gate
        else evaluate_report_quality(findings, require_proof_bundle=require_proof_bundle)
    )

    # Severity counts for the stats grid.
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed_count = 0
    for fd in findings_dicts:
        sev = str(fd["severity"]).lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        if fd["confidence_level"] == "Tool-Confirmed":
            confirmed_count += 1

    campaign_projection = {}
    if isinstance(campaign_ledger, dict):
        candidate_projection = campaign_ledger.get("coverage_projection")
        if isinstance(candidate_projection, dict):
            campaign_projection = candidate_projection
    smart_gate_ledger = campaign_projection or (coverage_ledger or {})

    matrix = authorization_matrix if isinstance(authorization_matrix, dict) else {}
    matrix_rows = [row for row in (matrix.get("rows") or []) if isinstance(row, dict)]
    matrix_comparisons = [
        item for item in (matrix.get("comparisons") or []) if isinstance(item, dict)
    ]
    comparison_summary: dict[str, int] = {}
    for item in matrix_comparisons:
        kind = str(item.get("comparison_kind") or "unknown")
        comparison_summary[kind] = comparison_summary.get(kind, 0) + 1
    authorization_appendix = {
        "identity_count": len(
            {str(row.get("identity_ref") or "") for row in matrix_rows if row.get("identity_ref")}
        ),
        "role_count": len({str(row.get("role") or "unknown") for row in matrix_rows}),
        "endpoint_count": len(
            {str(row.get("endpoint") or "") for row in matrix_rows if row.get("endpoint")}
        ),
        "coverage_gaps": list(matrix.get("coverage_gaps") or []),
        "comparison_summary": comparison_summary,
        "row_count": len(matrix_rows),
        "comparison_count": len(matrix_comparisons),
    }
    report_data: dict[str, Any] = {
        "target_url": target_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings_dicts),
        "confirmed_count": confirmed_count,
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "executive_summary": executive_summary,
        "findings": findings_dicts,
        "quality_gate": quality_result.model_dump(mode="json"),
        "hypotheses": hypotheses or [],
        # V7 Cognitive Upgrade — Phase 6: Decision Log explainability
        # appendix. Per the plan: "surfaced in the final report as an
        # explainability appendix." Each entry has timestamp,
        # decision_type, rule_fired, llm_contribution, outcome.
        "decision_log": decision_log or [],
        # V11 BAC evidence is surfaced separately from findings so an
        # incomplete identity matrix cannot be mistaken for a clean target.
        "bac_observations": _redact_report_value(bac_observations or []),
        "bac_coverage_gaps": _redact_report_value(bac_coverage_gaps or []),
        "relational_evidence": _redact_report_value(relational_evidence or []),
        # Read-only BAC appendix; reporter never promotes findings from it.
        "authorization_matrix_appendix": _redact_report_value(
            authorization_appendix if matrix else {}
        ),
        "bac_report_gate": {
            "status": "ready" if not bac_coverage_gaps else "partial",
            "requires_human_review": bool(bac_coverage_gaps),
            "coverage_gap_count": len(bac_coverage_gaps or []),
            "observation_count": len(bac_observations or []),
            "relational_edge_count": len(relational_evidence or []),
        },
        "subdomain_takeover_observations": _redact_report_value(
            subdomain_takeover_observations or []
        ),
        "subdomain_takeover_coverage_gaps": _redact_report_value(
            subdomain_takeover_coverage_gaps or []
        ),
        "cloud_storage_observations": _redact_report_value(cloud_storage_observations or []),
        "cloud_storage_coverage_gaps": _redact_report_value(cloud_storage_coverage_gaps or []),
        "jwt_deep_observations": _redact_report_value(jwt_deep_observations or []),
        "jwt_deep_coverage_gaps": _redact_report_value(jwt_deep_coverage_gaps or []),
        "jwt_report_gate": {
            "status": "ready" if not jwt_deep_coverage_gaps else "partial",
            "requires_human_review": bool(jwt_deep_coverage_gaps),
            "coverage_gap_count": len(jwt_deep_coverage_gaps or []),
            "observation_count": len(jwt_deep_observations or []),
        },
        "disclosed_report_advisories": _redact_report_value(disclosed_report_advisories or []),
        "advisory_coverage_gaps": _redact_report_value(advisory_coverage_gaps or []),
        "advisory_report_gate": {
            "status": "ready" if not advisory_coverage_gaps else "partial",
            "requires_human_review": bool(advisory_coverage_gaps),
            "coverage_gap_count": len(advisory_coverage_gaps or []),
            "advisory_count": len(disclosed_report_advisories or []),
        },
        "smart_coverage": _redact_report_value(coverage_ledger or {}),
        "campaign_ledger": _redact_report_value(campaign_ledger or {}),
        "proof_observability": _redact_report_value(proof_observability or {}),
        "smart_coverage_gate": {
            "status": "ready" if smart_gate_ledger else "not_available",
            "requires_human_review": bool(
                smart_gate_ledger and smart_gate_ledger.get("summary", {}).get("candidate", 0)
            ),
            "campaign_count": len(smart_gate_ledger.get("entries", [])),
            "attempt_count": int(smart_gate_ledger.get("attempt_count", 0) or 0),
        },
        "infrastructure_report_gate": {
            "status": "ready"
            if not (subdomain_takeover_coverage_gaps or cloud_storage_coverage_gaps)
            else "partial",
            "requires_human_review": bool(
                subdomain_takeover_coverage_gaps or cloud_storage_coverage_gaps
            ),
            "coverage_gap_count": len(subdomain_takeover_coverage_gaps or [])
            + len(cloud_storage_coverage_gaps or []),
            "takeover_observation_count": len(subdomain_takeover_observations or []),
            "cloud_observation_count": len(cloud_storage_observations or []),
        },
    }

    # Apply one final redaction pass before hashing. This covers target URLs,
    # summaries, decision metadata, and any newly-added report fields. The
    # authorization appendix is a read-only aggregate, not a secret container;
    # redact its nested values without masking the aggregate itself because the
    # generic key matcher intentionally treats "authorization" as sensitive.
    authorization_appendix = report_data.pop("authorization_matrix_appendix", {})
    report_data = _redact_report_value(report_data)
    report_data["authorization_matrix_appendix"] = _redact_report_value(
        authorization_appendix
    )

    # Build the audit trail AFTER the report data is complete so the
    # master hash covers everything.
    audit_trail = build_audit_trail(findings_dicts, report_data)
    report_data["audit_trail"] = audit_trail

    # Recompute the master hash now that audit_trail is included.
    # (The audit_trail contains the master hash, so we update it in
    # place to reflect the final report state.)
    report_data["audit_trail"]["master_report_hash"] = hash_report(report_data)

    return report_data


# ===========================================================================
# JSON export
# ===========================================================================
def export_to_json(
    target_url: str,
    findings: list[Finding],
    output_dir: Path,
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    bac_observations: list[dict[str, Any]] | None = None,
    bac_coverage_gaps: list[dict[str, Any]] | None = None,
    relational_evidence: list[dict[str, Any]] | None = None,
    subdomain_takeover_observations: list[dict[str, Any]] | None = None,
    subdomain_takeover_coverage_gaps: list[dict[str, Any]] | None = None,
    cloud_storage_observations: list[dict[str, Any]] | None = None,
    cloud_storage_coverage_gaps: list[dict[str, Any]] | None = None,
    jwt_deep_observations: list[dict[str, Any]] | None = None,
    jwt_deep_coverage_gaps: list[dict[str, Any]] | None = None,
    disclosed_report_advisories: list[dict[str, Any]] | None = None,
    advisory_coverage_gaps: list[dict[str, Any]] | None = None,
    strict_quality_gate: bool = False,
    require_proof_bundle: bool = False,
    coverage_ledger: dict[str, Any] | None = None,
    campaign_ledger: dict[str, Any] | None = None,
    proof_observability: dict[str, Any] | None = None,
    authorization_matrix: dict[str, Any] | None = None,
) -> Path:
    """Export findings to a JSON report with audit trail.

    Returns:
        The path to the written ``report.json`` file.
    """
    report_data = build_report_data(
        target_url,
        findings,
        executive_summary,
        risk_score,
        hypotheses,
        decision_log,
        bac_observations,
        bac_coverage_gaps,
        relational_evidence,
        subdomain_takeover_observations,
        subdomain_takeover_coverage_gaps,
        cloud_storage_observations,
        cloud_storage_coverage_gaps,
        jwt_deep_observations,
        jwt_deep_coverage_gaps,
        disclosed_report_advisories,
        advisory_coverage_gaps,
        strict_quality_gate=strict_quality_gate,
        require_proof_bundle=require_proof_bundle,
        coverage_ledger=coverage_ledger,
        campaign_ledger=campaign_ledger,
        proof_observability=proof_observability,
        authorization_matrix=authorization_matrix,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.json"
    path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    logger.info("JSON report written to %s", path)
    return path


# ===========================================================================
# Markdown export
# ===========================================================================
def export_to_markdown(
    target_url: str,
    findings: list[Finding],
    output_dir: Path,
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    **report_kwargs: Any,
) -> Path:
    """Export canonical redacted report data as a readable Markdown file."""
    report_data = build_report_data(
        target_url,
        findings,
        executive_summary,
        risk_score,
        hypotheses,
        decision_log,
        **report_kwargs,
    )
    lines = [
        "# WebPent Security Report",
        "",
        f"**Target:** {report_data.get('target_url', target_url)}",
        f"**Generated:** {report_data.get('generated_at', '')}",
        f"**Risk score:** {report_data.get('risk_score', risk_score)}",
        "",
        "## Executive Summary",
        "",
        str(report_data.get("executive_summary") or "No executive summary was produced."),
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity, count in (report_data.get("severity_counts") or {}).items():
        lines.append(f"| {severity} | {count} |")
    lines.extend(["", "## Findings", ""])
    report_findings = report_data.get("findings") or []
    if not report_findings:
        lines.append("No findings were discovered.")
    for index, finding in enumerate(report_findings, 1):
        lines.extend(
            [
                f"### {index}. {finding.get('title') or 'Untitled finding'}",
                "",
                f"- **Severity:** {finding.get('severity', '')}",
                f"- **Confidence:** {finding.get('confidence_level', '')}",
                f"- **Lifecycle:** {finding.get('lifecycle_stage', '')}",
                f"- **URL:** {finding.get('url', '')}",
                f"- **Tool:** {finding.get('tool_name', '')}",
                "",
                str(finding.get("description") or ""),
                "",
                "#### Evidence",
                "",
                "```json",
                json.dumps(finding.get("evidence_bundle"), indent=2, default=str),
                "```",
                "",
            ]
        )
    decisions = report_data.get("decision_log") or []
    if decisions:
        lines.extend(["## Explainability Log", "", "| Decision | Reason |", "| --- | --- |"])
        for item in decisions:
            if isinstance(item, dict):
                lines.append(f"| {item.get('decision', '')} | {item.get('reason', '')} |")
        lines.append("")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.md"
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    logger.info("Markdown report written to %s", path)
    return path


# ===========================================================================
# HTML export (Jinja2)
# ===========================================================================
def export_to_html(
    target_url: str,
    findings: list[Finding],
    output_dir: Path,
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    bac_observations: list[dict[str, Any]] | None = None,
    bac_coverage_gaps: list[dict[str, Any]] | None = None,
    relational_evidence: list[dict[str, Any]] | None = None,
    subdomain_takeover_observations: list[dict[str, Any]] | None = None,
    subdomain_takeover_coverage_gaps: list[dict[str, Any]] | None = None,
    cloud_storage_observations: list[dict[str, Any]] | None = None,
    cloud_storage_coverage_gaps: list[dict[str, Any]] | None = None,
    jwt_deep_observations: list[dict[str, Any]] | None = None,
    jwt_deep_coverage_gaps: list[dict[str, Any]] | None = None,
    disclosed_report_advisories: list[dict[str, Any]] | None = None,
    advisory_coverage_gaps: list[dict[str, Any]] | None = None,
    strict_quality_gate: bool = False,
    require_proof_bundle: bool = False,
    coverage_ledger: dict[str, Any] | None = None,
    campaign_ledger: dict[str, Any] | None = None,
    proof_observability: dict[str, Any] | None = None,
    authorization_matrix: dict[str, Any] | None = None,
) -> Path:
    """Export findings to a professional HTML report via Jinja2.

    Returns:
        The path to the written ``report.html`` file.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.error("Jinja2 not installed — cannot export HTML report")
        raise

    report_data = build_report_data(
        target_url,
        findings,
        executive_summary,
        risk_score,
        hypotheses,
        decision_log,
        bac_observations,
        bac_coverage_gaps,
        relational_evidence,
        subdomain_takeover_observations,
        subdomain_takeover_coverage_gaps,
        cloud_storage_observations,
        cloud_storage_coverage_gaps,
        jwt_deep_observations,
        jwt_deep_coverage_gaps,
        disclosed_report_advisories,
        advisory_coverage_gaps,
        strict_quality_gate=strict_quality_gate,
        require_proof_bundle=require_proof_bundle,
        coverage_ledger=coverage_ledger,
        campaign_ledger=campaign_ledger,
        proof_observability=proof_observability,
        authorization_matrix=authorization_matrix,
    )

    template_dir = _TEMPLATE_PATH.parent
    template_name = _TEMPLATE_PATH.name

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)
    html = template.render(**report_data)

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", path)
    return path


# ===========================================================================
# PDF export
# ===========================================================================
def export_to_pdf(
    target_url: str,
    findings: list[Finding],
    output_dir: Path,
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    bac_observations: list[dict[str, Any]] | None = None,
    bac_coverage_gaps: list[dict[str, Any]] | None = None,
    relational_evidence: list[dict[str, Any]] | None = None,
    subdomain_takeover_observations: list[dict[str, Any]] | None = None,
    subdomain_takeover_coverage_gaps: list[dict[str, Any]] | None = None,
    cloud_storage_observations: list[dict[str, Any]] | None = None,
    cloud_storage_coverage_gaps: list[dict[str, Any]] | None = None,
    jwt_deep_observations: list[dict[str, Any]] | None = None,
    jwt_deep_coverage_gaps: list[dict[str, Any]] | None = None,
    disclosed_report_advisories: list[dict[str, Any]] | None = None,
    advisory_coverage_gaps: list[dict[str, Any]] | None = None,
    strict_quality_gate: bool = False,
    require_proof_bundle: bool = False,
    coverage_ledger: dict[str, Any] | None = None,
    campaign_ledger: dict[str, Any] | None = None,
    proof_observability: dict[str, Any] | None = None,
    authorization_matrix: dict[str, Any] | None = None,
) -> Path | None:
    """Export findings to a PDF report.

    V5 Sprint 11: Tries weasyprint first (pure-Python, no system deps).
    Falls back to pdfkit (requires wkhtmltopdf system binary). If
    neither is available, logs a warning and returns ``None`` — the
    HTML report is still produced and can be printed to PDF manually.

    Returns:
        The path to the written ``report.pdf`` file, or ``None`` if no
        PDF backend was available.
    """
    # First generate the HTML so we have a source for the PDF.
    html_path = export_to_html(
        target_url,
        findings,
        output_dir,
        executive_summary,
        risk_score,
        hypotheses,
        decision_log,
        bac_observations,
        bac_coverage_gaps,
        relational_evidence,
        subdomain_takeover_observations,
        subdomain_takeover_coverage_gaps,
        cloud_storage_observations,
        cloud_storage_coverage_gaps,
        jwt_deep_observations,
        jwt_deep_coverage_gaps,
        disclosed_report_advisories,
        advisory_coverage_gaps,
        strict_quality_gate=strict_quality_gate,
        require_proof_bundle=require_proof_bundle,
        coverage_ledger=coverage_ledger,
        campaign_ledger=campaign_ledger,
        proof_observability=proof_observability,
        authorization_matrix=authorization_matrix,
    )
    html_content = html_path.read_text(encoding="utf-8")

    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = output_dir / "report.pdf"

    # --- Try weasyprint (preferred — pure Python) ---
    try:
        from weasyprint import HTML

        HTML(string=html_content).write_pdf(str(pdf_path))
        logger.info("PDF report written to %s (via weasyprint)", pdf_path)
        return pdf_path
    except ImportError:
        logger.debug("weasyprint not installed — trying pdfkit fallback")
    except Exception as exc:
        logger.warning("weasyprint PDF generation failed: %s — trying pdfkit", exc)

    # --- Fallback: pdfkit (requires wkhtmltopdf system binary) ---
    try:
        import pdfkit

        pdfkit.from_string(html_content, str(pdf_path))
        logger.info("PDF report written to %s (via pdfkit)", pdf_path)
        return pdf_path
    except ImportError:
        logger.warning(
            "Neither weasyprint nor pdfkit is installed. PDF export "
            "skipped — HTML report is available at %s. Install with "
            "'pip install weasyprint' or 'pip install pdfkit'.",
            html_path,
        )
        return None
    except Exception as exc:
        logger.warning(
            "PDF generation failed (%s). HTML report is available at %s.",
            exc,
            html_path,
        )
        return None


# ===========================================================================
# All-in-one export
# ===========================================================================
def export_all_formats(
    target_url: str,
    findings: list[Finding],
    output_dir: Path,
    executive_summary: str = "",
    risk_score: str = "Low",
    hypotheses: list[str] | None = None,
    decision_log: list[dict[str, Any]] | None = None,
    bac_observations: list[dict[str, Any]] | None = None,
    bac_coverage_gaps: list[dict[str, Any]] | None = None,
    relational_evidence: list[dict[str, Any]] | None = None,
    subdomain_takeover_observations: list[dict[str, Any]] | None = None,
    subdomain_takeover_coverage_gaps: list[dict[str, Any]] | None = None,
    cloud_storage_observations: list[dict[str, Any]] | None = None,
    cloud_storage_coverage_gaps: list[dict[str, Any]] | None = None,
    jwt_deep_observations: list[dict[str, Any]] | None = None,
    jwt_deep_coverage_gaps: list[dict[str, Any]] | None = None,
    disclosed_report_advisories: list[dict[str, Any]] | None = None,
    advisory_coverage_gaps: list[dict[str, Any]] | None = None,
    strict_quality_gate: bool = False,
    require_proof_bundle: bool = False,
    coverage_ledger: dict[str, Any] | None = None,
    campaign_ledger: dict[str, Any] | None = None,
    proof_observability: dict[str, Any] | None = None,
    authorization_matrix: dict[str, Any] | None = None,
    formats: list[str] | None = None,
) -> dict[str, Path | None]:
    """Export selected formats; ``None`` preserves historical JSON/HTML/PDF."""
    requested = {str(item).strip().lower() for item in (formats or ["json", "html", "pdf"])}
    if "all" in requested:
        requested = {"json", "html", "pdf", "md"}
    shared = {
        "bac_observations": bac_observations,
        "bac_coverage_gaps": bac_coverage_gaps,
        "relational_evidence": relational_evidence,
        "subdomain_takeover_observations": subdomain_takeover_observations,
        "subdomain_takeover_coverage_gaps": subdomain_takeover_coverage_gaps,
        "cloud_storage_observations": cloud_storage_observations,
        "cloud_storage_coverage_gaps": cloud_storage_coverage_gaps,
        "jwt_deep_observations": jwt_deep_observations,
        "jwt_deep_coverage_gaps": jwt_deep_coverage_gaps,
        "disclosed_report_advisories": disclosed_report_advisories,
        "advisory_coverage_gaps": advisory_coverage_gaps,
        "strict_quality_gate": strict_quality_gate,
        "require_proof_bundle": require_proof_bundle,
        "coverage_ledger": coverage_ledger,
        "campaign_ledger": campaign_ledger,
        "proof_observability": proof_observability,
        "authorization_matrix": authorization_matrix,
    }
    paths: dict[str, Path | None] = {}
    if "json" in requested:
        paths["json"] = export_to_json(
            target_url, findings, output_dir, executive_summary, risk_score,
            hypotheses, decision_log, **shared
        )
    if "html" in requested:
        paths["html"] = export_to_html(
            target_url, findings, output_dir, executive_summary, risk_score,
            hypotheses, decision_log, **shared
        )
    if "pdf" in requested:
        paths["pdf"] = export_to_pdf(
            target_url, findings, output_dir, executive_summary, risk_score,
            hypotheses, decision_log, **shared
        )
    if "md" in requested:
        paths["md"] = export_to_markdown(
            target_url, findings, output_dir, executive_summary, risk_score,
            hypotheses, decision_log, **shared
        )
    return paths
