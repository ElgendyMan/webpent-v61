"""V7 Phase 3 — Deterministic Skill Selection (100% rule-based)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_MANIFEST_PATH = Path(__file__).resolve().parents[3] / "knowledge_sources.yaml"


def _load_skills() -> list[dict[str, Any]]:
    try:
        import yaml

        if not _MANIFEST_PATH.is_file():
            return []
        with open(_MANIFEST_PATH) as f:
            return yaml.safe_load(f).get("skills", [])
    except Exception:
        return []


def select_skills(
    current_phase: str, vuln_class: str | None = None
) -> list[dict[str, Any]]:
    matched = []
    for skill in _load_skills():
        if skill.get("applies_to_phase") != current_phase:
            continue
        if vuln_class and vuln_class not in skill.get("applies_to_vuln_class", []):
            continue
        matched.append(skill)
    if matched:
        logger.info(
            "Skill selector: %d matched (phase=%s, vc=%s)",
            len(matched),
            current_phase,
            vuln_class or "any",
        )
    return matched


def get_skill_reference(skill: dict[str, Any], finding_id: str) -> str:
    source = skill.get("reference_source", "")
    if source == "payload_corpus":
        return ""
    if source == "hacktricks":
        from webpent.shared.reference_lookup import reference_lookup

        return reference_lookup(
            query=skill.get("name", ""), finding_id=finding_id, source="hacktricks"
        )
    return ""
