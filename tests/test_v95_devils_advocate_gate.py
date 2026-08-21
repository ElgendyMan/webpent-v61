from __future__ import annotations

from webpent.agents.devils_advocate import agent as da_module
from webpent.graph.builder import (
    NODE_EXPLOIT_CHAINER,
    NODE_VALIDATOR,
    route_after_devils_advocate,
)
from webpent.models.findings import Finding, Severity, VulnClass


def _finding() -> Finding:
    return Finding(
        title="IDOR candidate",
        severity=Severity.HIGH,
        description="Contract-test candidate.",
        tool_name="test",
        url="https://target.test/profile?id=2",
        vuln_class=VulnClass.IDOR,
        confidence_level="AI-Assessed",
        evidence={"tool_output": "observed response difference"},
    )


def test_rejected_devils_advocate_reenters_validator_once(monkeypatch) -> None:
    finding = _finding()
    monkeypatch.setattr(da_module, "try_get_llm", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        da_module,
        "_devils_advocate_finding",
        lambda current, _llm, *, allow_downgrade: current.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "reasoning": "grounded counter-argument",
            }
        ),
    )

    result = da_module.devils_advocate_node(
        {"findings": [finding], "devils_advocate_revalidation_count": 0}
    )
    gated = result["findings"][0]

    assert gated.confidence_level == "Pending"
    assert gated.evidence["devils_advocate_gate"] == "rejected"
    assert gated.evidence["devils_advocate_revalidation_required"] is True
    assert result["devils_advocate_revalidation_count"] == 1
    assert str(finding.id) in result["devils_advocate_revalidation_ids"]
    assert route_after_devils_advocate(result) == NODE_VALIDATOR


def test_devils_advocate_gate_is_bounded_after_revalidation() -> None:
    state = {
        "devils_advocate_revalidation_ids": ["finding-1"],
        "devils_advocate_revalidation_count": 1,
        "devils_advocate_gate_active": False,
    }
    assert route_after_devils_advocate(state) == NODE_EXPLOIT_CHAINER
    assert route_after_devils_advocate({}) == NODE_EXPLOIT_CHAINER


def test_no_llm_cannot_manufacture_devils_advocate_rejection(monkeypatch) -> None:
    finding = _finding()
    monkeypatch.setattr(da_module, "try_get_llm", lambda *_args, **_kwargs: None)

    result = da_module.devils_advocate_node(
        {"findings": [finding], "devils_advocate_revalidation_count": 0}
    )

    assert result["findings"][0] == finding
    assert "devils_advocate_revalidation_count" not in result
    assert result["devils_advocate_gate_active"] is False
    assert route_after_devils_advocate(result) == NODE_EXPLOIT_CHAINER
