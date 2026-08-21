from __future__ import annotations

import ast
from pathlib import Path

import pytest

from webpent.shared.evidence_quality import assess_finding_evidence
from webpent.shared.runtime import AdapterRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENTS_ROOT = REPO_ROOT / "src" / "webpent" / "agents"

# These are legacy capability owners. They remain explicitly audited here until
# their transports are migrated behind registered adapters.
DIRECT_IO_ALLOWLIST = {
    "src/webpent/agents/request_smuggling/agent.py": {"socket"},
    "src/webpent/agents/subdomain_takeover/agent.py": {"socket"},
    "src/webpent/agents/authentication/agent.py": {"playwright"},
    "src/webpent/agents/execution_sandbox/agent.py": {"playwright"},
    "src/webpent/agents/validator/agent.py": {"playwright"},
}
BANNED_IMPORT_ROOTS = {"requests", "httpx", "aiohttp", "socket", "subprocess", "playwright"}


def _module_name(node: ast.Import | ast.ImportFrom) -> str:
    if isinstance(node, ast.Import):
        return node.names[0].name.split(".", 1)[0]
    return (node.module or "").split(".", 1)[0]


def test_agent_direct_io_imports_are_allowlisted() -> None:
    violations: list[str] = []
    for path in AGENTS_ROOT.rglob("*.py"):
        relative = path.relative_to(REPO_ROOT).as_posix()
        allowed = DIRECT_IO_ALLOWLIST.get(relative, set())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            module = _module_name(node)
            if module in BANNED_IMPORT_ROOTS and module not in allowed:
                violations.append(f"{relative}:{node.lineno}:{module}")
    assert violations == [], "unregistered direct-I/O imports: " + ", ".join(violations)


def test_unknown_runtime_adapter_is_blocked_fail_closed() -> None:
    registry = AdapterRegistry()

    assert registry.available("raw_socket") is False
    assert registry.get("raw_socket") is None


def test_incomplete_evidence_cannot_be_promoted() -> None:
    assessment = assess_finding_evidence(
        {
            "confidence_level": "Tool-Confirmed",
            "evidence": {
                "causal_signal": True,
                "negative_control_complete": True,
                "proof_bundle": {"sealed": True},
            },
        }
    )

    assert assessment.classification != "confirmed"
    assert assessment.promotion_ready_proof_bundle is False
    assert "promotion_ready_proof_bundle" in assessment.missing_signals


@pytest.mark.parametrize(
    "evidence",
    [
        {"causal_signal": False, "negative_control_complete": True},
        {"causal_signal": True, "negative_control_complete": False},
        {
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle": {"sealed": False},
        },
    ],
)
def test_negative_or_partial_evidence_is_not_confirmed(evidence: dict[str, object]) -> None:
    assessment = assess_finding_evidence(
        {"confidence_level": "Tool-Confirmed", "evidence": evidence}
    )

    assert assessment.classification in {"unconfirmed", "needs_human_review"}
    assert assessment.promotion_ready_proof_bundle is False
