from types import SimpleNamespace

from test_v26_report_quality import _finding

from webpent.shared.bac_identity_tester import target_fingerprint


def test_reporter_blocks_tool_confirmed_without_proof_bundle(monkeypatch):
    from webpent.agents.reporter import agent as reporter_agent

    monkeypatch.setattr(
        reporter_agent,
        "get_settings",
        lambda: SimpleNamespace(
            smart_require_proof_bundle=True,
            enable_report_quality_gate=False,
            enable_bug_bounty_reporter=False,
        ),
    )

    result = reporter_agent.reporter_node(
        {
            "target": {"url": "https://target.test"},
            "findings": [_finding()],
            "hypotheses": [],
            "proof_bundles": [],
        }
    )

    assert result["current_phase"] == "reporting"
    assert result["report_quality_gate"]["status"] == "blocked"
    assert "proof_bundle" in str(result["report_quality_gate"]).lower()


def test_reporter_rejects_historical_or_wrong_target_proof_bundle():
    from webpent.agents.reporter import agent as reporter_agent

    finding = _finding()
    expected_target = target_fingerprint("https://target.test")
    historical = {
        "finding_id": "finding-quality-1",
        "engagement_id": "old-engagement",
        "target_fingerprint": expected_target,
        "sealed": True,
    }
    wrong_target = {
        "finding_id": "finding-quality-1",
        "engagement_id": "current-engagement",
        "target_fingerprint": target_fingerprint("https://other.test"),
        "sealed": True,
    }

    historical_view = reporter_agent._findings_with_proof_bundles(
        [finding],
        [historical],
        engagement_id="current-engagement",
        target_url="https://target.test",
    )
    wrong_target_view = reporter_agent._findings_with_proof_bundles(
        [finding],
        [wrong_target],
        engagement_id="current-engagement",
        target_url="https://target.test",
    )

    assert "proof_bundle" not in historical_view[0]
    assert "proof_bundle" not in wrong_target_view[0]


def test_reporter_attaches_only_current_target_proof_bundle():
    from webpent.agents.reporter import agent as reporter_agent

    finding = _finding()
    bundle = {
        "finding_id": "finding-quality-1",
        "engagement_id": "current-engagement",
        "target_fingerprint": target_fingerprint("https://target.test"),
        "sealed": True,
    }

    view = reporter_agent._findings_with_proof_bundles(
        [finding],
        [bundle],
        engagement_id="current-engagement",
        target_url="https://target.test",
    )

    assert view[0]["proof_bundle"] == bundle


def test_reporter_promotes_current_embedded_evidence_bundle_to_proof_bundle():
    from webpent.agents.reporter import agent as reporter_agent

    finding = _finding()
    bundle = {
        "finding_id": str(finding["id"]),
        "engagement_id": "current-engagement",
        "target_fingerprint": target_fingerprint("https://target.test"),
        "sealed": True,
    }
    finding_with_bundle = {**finding, "evidence_bundle": bundle}

    view = reporter_agent._findings_with_proof_bundles(
        [finding_with_bundle],
        [],
        engagement_id="current-engagement",
        target_url="https://target.test",
    )

    assert view[0]["proof_bundle"] == bundle


def test_reporter_rejects_stale_embedded_evidence_bundle():
    from webpent.agents.reporter import agent as reporter_agent

    finding = _finding()
    stale = {
        "finding_id": str(finding["id"]),
        "engagement_id": "old-engagement",
        "target_fingerprint": target_fingerprint("https://target.test"),
        "sealed": True,
    }
    finding_with_bundle = {**finding, "evidence_bundle": stale}

    view = reporter_agent._findings_with_proof_bundles(
        [finding_with_bundle],
        [],
        engagement_id="current-engagement",
        target_url="https://target.test",
    )

    assert "proof_bundle" not in view[0]


def test_report_export_preserves_bac_evidence_and_report_metadata():
    from webpent.reporter.export import build_report_data

    finding = _finding()
    finding.update(
        {
            "confidence_level": "Tool-Confirmed",
            "business_impact": "Cross-identity access was reproduced.",
            "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "evidence": {
                "causal_signal": True,
                "negative_control_complete": True,
                "reproduction": {"steps_to_reproduce": ["replay the request"]},
            },
            "evidence_bundle": {
                "finding_id": str(finding["id"]),
                "sealed": True,
            },
        }
    )

    report = build_report_data(
        "https://target.test",
        [finding],
        strict_quality_gate=False,
        require_proof_bundle=False,
    )
    exported = report["findings"][0]

    assert exported["evidence"]["causal_signal"] is True
    assert exported["evidence"]["negative_control_complete"] is True
    assert exported["business_impact"] == finding["business_impact"]
    assert exported["cvss_score"] == finding["cvss_score"]


def test_vip_profile_requires_proof_bundle_even_when_setting_is_false(monkeypatch):
    from webpent.agents.reporter import agent as reporter_agent

    monkeypatch.setattr(
        reporter_agent,
        "get_settings",
        lambda: SimpleNamespace(
            smart_require_proof_bundle=False,
            enable_report_quality_gate=False,
            enable_bug_bounty_reporter=False,
        ),
    )

    result = reporter_agent.reporter_node(
        {
            "target": {"url": "https://target.test"},
            "findings": [_finding()],
            "hypotheses": [],
            "proof_bundles": [],
            "smart_governance": {"profile": "vip-qualification"},
        }
    )

    assert result["report_quality_gate"]["status"] == "blocked"
    assert "proof_bundle" in str(result["report_quality_gate"]).lower()


def test_report_export_surfaces_valid_embedded_proof_bundle():
    from webpent.models.proof_bundle import build_proof_bundle
    from webpent.reporter.export import build_report_data

    finding = _finding()
    target = "https://target.test"
    baseline = {
        "observation_role": "baseline",
        "target_backed": True,
        "target_fingerprint": target_fingerprint(target),
        "request_digest": "sha256:" + "1" * 64,
        "response_digest": "sha256:" + "2" * 64,
    }
    candidate = {
        "observation_role": "candidate",
        "target_backed": True,
        "target_fingerprint": target_fingerprint(target),
        "request_digest": "sha256:" + "3" * 64,
        "response_digest": "sha256:" + "4" * 64,
    }
    negative = {
        "observation_role": "negative_control",
        "target_backed": True,
        "target_fingerprint": target_fingerprint(target),
        "request_digest": "sha256:" + "5" * 64,
        "response_digest": "sha256:" + "6" * 64,
    }
    bundle = build_proof_bundle(
        engagement_id="current-engagement",
        finding_id=str(finding["id"]),
        hypothesis_id="finding:hypothesis",
        target_fingerprint=target_fingerprint(target),
        scope_context={"target_url": target},
        identity_context={"owner": "owner", "foreign": "foreign"},
        evidence=[baseline, candidate, negative],
        evidence_refs=["replay:test:baseline", "replay:test:candidate", "replay:test:negative"],
        negative_control=negative,
        baseline=baseline,
        request_evidence=[baseline, candidate, negative],
        response_evidence=[baseline, candidate, negative],
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": True,
        },
        target_backed=True,
        negative_control_independent=True,
        validator_id="test-validator",
        validator_version="1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal(actor="test")
    assert bundle.verify_seal()

    finding.update({"evidence_bundle": bundle.model_dump(mode="json")})
    exported = build_report_data(target, [finding])["findings"][0]
    assert exported["proof_bundle"] == exported["evidence_bundle"]
