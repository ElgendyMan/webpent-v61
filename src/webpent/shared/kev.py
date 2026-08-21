"""Known Exploited Vulnerabilities enrichment without confirmation semantics."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cves(value: Any) -> list[str]:
    return sorted({match.upper() for match in _CVE_RE.findall(str(value or ""))})


def enrich_finding_with_kev(finding: Any, kev_ids: Iterable[str]) -> Any:
    """Attach KEV membership as advisory evidence, never as proof."""
    known = {str(value).upper() for value in kev_ids}
    cves = extract_cves(getattr(finding, "description", ""))
    matched = sorted(set(cves) & known)
    if not matched or not hasattr(finding, "model_copy"):
        return finding
    evidence = dict(getattr(finding, "evidence", None) or {})
    evidence["kev_context"] = {
        "matched_cves": matched,
        "source": "injected_catalog",
        "advisory_only": True,
        "does_not_confirm": True,
    }
    return finding.model_copy(update={"evidence": evidence})


__all__ = ["enrich_finding_with_kev", "extract_cves"]
