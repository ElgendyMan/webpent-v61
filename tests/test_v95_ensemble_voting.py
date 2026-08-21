from __future__ import annotations

from types import SimpleNamespace

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.ensemble import apply_ensemble_review


def _finding(severity: Severity) -> Finding:
    return Finding(
        title="High-risk candidate",
        severity=severity,
        description="A bounded contract-test finding.",
        tool_name="test",
        url="https://target.test/item",
        vuln_class=VulnClass.IDOR,
        evidence={"tool": "observed"},
    )


def test_high_finding_gets_independent_provider_signal() -> None:
    calls: list[str] = []

    class Reviewer:
        def invoke(self, _prompt: str) -> SimpleNamespace:
            calls.append("invoked")
            return SimpleNamespace(content='{"verdict":"agree","reason":"evidence matches"}')

    def get_reviewer(task_type, *, exclude_provider=None):
        assert task_type.value == "analysis"
        assert exclude_provider == "openai"
        return "anthropic", Reviewer()

    result = apply_ensemble_review(
        [_finding(Severity.HIGH)],
        primary_provider="openai",
        get_reviewer=get_reviewer,
    )

    review = result[0].evidence["ensemble_review"]
    assert calls == ["invoked"]
    assert review["provider"] == "anthropic"
    assert review["verdict"] == "agree"
    assert review["evidence_preserved"] is True
    assert result[0].evidence["evidence_bundle"]["ensemble_review"]["verdict"] == "agree"


def test_low_finding_is_not_sent_to_ensemble() -> None:
    calls: list[str] = []

    def get_reviewer(*_args, **_kwargs):
        calls.append("constructed")
        raise AssertionError("low findings must not construct a reviewer")

    result = apply_ensemble_review(
        [_finding(Severity.LOW)], get_reviewer=get_reviewer
    )

    assert result[0].evidence == {"tool": "observed"}
    assert calls == []
