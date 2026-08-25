"""Evidence-based, deterministic program scoring.

The scorer does not infer a vulnerability. It estimates only whether a program is a
safe and useful fit for the declared, *qualified* WebPent capability profile.
"""

from __future__ import annotations

import re

from .models import CapabilityProfile, ProgramSummary, ScopeAssessment, ScopeStatus, ScoreBreakdown

WEIGHTS = {
    "webpent_capability_fit": 20,
    "attack_surface_richness": 15,
    "auth_workflow_testability": 15,
    "scope_clarity": 15,
    "validator_coverage": 15,
    "confirmation_feasibility": 10,
    "stability_operational_cost": 5,
    "historical_calibration": 5,
}

SURFACE_PATTERNS = {
    "api": re.compile(r"\b(api|rest|openapi)\b", re.IGNORECASE),
    "graphql": re.compile(r"\bgraphql\b", re.IGNORECASE),
    "browser": re.compile(r"\b(web|website|url|browser|spa)\b", re.IGNORECASE),
    "upload": re.compile(r"\b(upload|file|attachment|import)\b", re.IGNORECASE),
    "identity": re.compile(
        r"\b(login|sign[ -]?up|account|tenant|role|identity|sso|oauth)\b", re.IGNORECASE
    ),
}


def _feature(value: float, evidence: list[str], confidence: str) -> dict[str, object]:
    return {
        "value": round(max(0.0, min(1.0, value)), 3),
        "evidence": evidence,
        "confidence": confidence,
    }


def _surface_text(program: ProgramSummary, scope: ScopeAssessment) -> str:
    rule_values = " ".join(rule.raw_value for rule in scope.normalized_rules)
    return " ".join(
        [
            program.name,
            program.handle,
            " ".join(program.tags),
            program.policy_text or "",
            rule_values,
        ]
    )


def _evidence_surface(
    program: ProgramSummary, scope: ScopeAssessment
) -> tuple[dict[str, bool], list[str]]:
    text = _surface_text(program, scope)
    signals = {name: bool(pattern.search(text)) for name, pattern in SURFACE_PATTERNS.items()}
    evidence = [name for name, hit in signals.items() if hit]
    return signals, evidence


def _percentage(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def score_program(
    program: ProgramSummary,
    scope: ScopeAssessment,
    profile: CapabilityProfile,
    *,
    historical_calibration: float = 0.0,
) -> ScoreBreakdown:
    blockers: list[str] = []
    reasons: list[str] = []

    if program.access_state != "visible":
        blockers.append("الحساب لا يملك حالة رؤية مؤكدة للبرنامج.")
    if scope.status != ScopeStatus.READY.value:
        blockers.append(f"حالة الـ scope هي {scope.status} وليست ready.")
    if not program.policy_text or not program.policy_text.strip():
        blockers.append("policy غير موجودة؛ لا يمكن فرض شروط البرنامج.")
    qualified = {name for name, passed in profile.qualified_capabilities.items() if passed}
    if not qualified:
        blockers.append("لا توجد WebPent capabilities مؤهلة في الـ profile.")

    if blockers:
        return ScoreBreakdown(
            score=None,
            confidence="none",
            uncertainty_low=None,
            uncertainty_high=None,
            eligibility="blocked",
            reasons=[],
            blockers=blockers,
            features={},
        )

    signals, surface_evidence = _evidence_surface(program, scope)
    observed_surface = {name for name, present in signals.items() if present}
    required_capabilities = set(observed_surface) or {"browser"}
    matched_capabilities = required_capabilities & qualified
    capability_fit = _percentage(len(matched_capabilities), len(required_capabilities))
    if matched_capabilities:
        reasons.append("قدرات مؤهلة متوافقة: " + ", ".join(sorted(matched_capabilities)))

    surface_score = min(1.0, len(observed_surface) / 4.0)
    if surface_evidence:
        reasons.append("إشارات surface موثقة: " + ", ".join(surface_evidence))

    auth_signals = sum(1 for item in ("identity", "browser") if signals[item])
    auth_profile = sum(
        1 for item in ("identity", "browser") if profile.qualified_capabilities.get(item, False)
    )
    auth_score = _percentage(auth_signals, 2) * _percentage(auth_profile, 2)

    scope_score = 1.0
    if scope.exclusion_count == 0:
        scope_score -= 0.15
        reasons.append("لا توجد exclusions منظمة في الـ scope؛ ثقة أقل.")
    if any(rule.wildcard for rule in scope.normalized_rules):
        scope_score -= 0.10
        reasons.append(
            "يوجد wildcard؛ الـ apex والـ redirects يظلوا خارج التصريح إلا بقواعد مستقلة."
        )

    validator_keys = {key.lower() for key, value in profile.validators.items() if value}
    validator_map = {
        "api": {"idor", "mass_assignment", "injections", "ssrf"},
        "graphql": {"idor", "injections", "mass_assignment"},
        "browser": {"xss", "csrf", "business_logic"},
        "upload": {"xss", "ssrf", "business_logic"},
        "identity": {"idor", "tenant_isolation", "business_logic"},
    }
    applicable = (
        set().union(*(validator_map[item] for item in observed_surface))
        if observed_surface
        else set()
    )
    validator_score = (
        _percentage(len(applicable & validator_keys), len(applicable)) if applicable else 0.0
    )

    confirmation_keys = {key.lower() for key, value in profile.confirmation.items() if value}
    needed_confirmation = {"replay", "negative_controls"}
    if signals["identity"]:
        needed_confirmation.add("second_identity")
    confirmation_score = _percentage(
        len(needed_confirmation & confirmation_keys), len(needed_confirmation)
    )

    stability_score = 0.7 if program.status.lower() in {"open", "public_mode", "active"} else 0.4
    if program.updated_at:
        stability_score += 0.1
    stability_score = min(1.0, stability_score)
    historical_score = max(0.0, min(1.0, historical_calibration))

    features = {
        "webpent_capability_fit": _feature(
            capability_fit, sorted(matched_capabilities), "high" if matched_capabilities else "low"
        ),
        "attack_surface_richness": _feature(
            surface_score, surface_evidence, "medium" if surface_evidence else "low"
        ),
        "auth_workflow_testability": _feature(
            auth_score,
            [item for item in ("identity", "browser") if signals[item]],
            "low" if auth_score < 0.5 else "medium",
        ),
        "scope_clarity": _feature(
            scope_score,
            [f"{scope.include_count} include rules", f"{scope.exclusion_count} exclusion rules"],
            "high",
        ),
        "validator_coverage": _feature(
            validator_score, sorted(applicable & validator_keys), "high" if applicable else "low"
        ),
        "confirmation_feasibility": _feature(
            confirmation_score,
            sorted(needed_confirmation & confirmation_keys),
            "high" if confirmation_score >= 0.66 else "medium",
        ),
        "stability_operational_cost": _feature(
            stability_score, [f"status={program.status}"], "medium"
        ),
        "historical_calibration": _feature(
            historical_score,
            ["local profile calibration"],
            "low" if historical_score == 0 else "medium",
        ),
    }

    score = sum(WEIGHTS[name] * float(detail["value"]) for name, detail in features.items())
    evidence_count = (
        len(surface_evidence) + len(matched_capabilities) + len(applicable & validator_keys)
    )
    high_features = sum(1 for detail in features.values() if detail["confidence"] == "high")
    if high_features >= 3 and evidence_count >= 5:
        confidence = "high"
        spread = 7.0
    elif evidence_count >= 2:
        confidence = "medium"
        spread = 14.0
    else:
        confidence = "low"
        spread = 24.0
    if confidence == "low":
        reasons.append("الأدلة قليلة؛ الترتيب توصية مبدئية وليس يقينًا.")

    return ScoreBreakdown(
        score=round(score, 2),
        confidence=confidence,
        uncertainty_low=round(max(0.0, score - spread), 2),
        uncertainty_high=round(min(100.0, score + spread), 2),
        eligibility="eligible",
        reasons=reasons,
        blockers=[],
        features=features,
    )
