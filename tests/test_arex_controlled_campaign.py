from scripts.run_arex_controlled_campaign import run_campaign


def test_controlled_arex_campaign_is_bounded_and_proof_backed():
    report = run_campaign()

    assert all(report["readiness"].values())
    assert report["scheduler"]["status"] == "selected"
    assert report["scheduler"]["route"] == "observation"
    assert report["boundedness"]["actual_target_requests"] == 3
    assert report["boundedness"]["max_scheduler_steps"] == 1
    assert report["boundedness"]["external_network"] is False
    assert report["boundedness"]["credentials"] is False
    assert report["boundedness"]["state_mutation"] is False
    assert report["boundedness"]["persistent_service"] is False

    case_result = report["case_result"]
    assert case_result["status"] == "confirmed"
    assert case_result["proof_bundle_ref"]
    assert case_result["metadata"]["proof_bundle_sealed"] == "True"
    assert case_result["metadata"]["replay_verified"] == "True"
    assert len(case_result["observation_refs"]) == 3

    evaluation = report["evaluation"]
    assert evaluation["controlled_experiment"] is True
    assert evaluation["real_world_detection_rate_measured"] is False
    assert evaluation["qualification_effect"] is False
    assert evaluation["proof_completeness"] == 1.0

    governance = report["governance"]
    assert governance["official_isolated_p10_runs_authorized"] is False
    assert governance["p10_status"] == "NOT_QUALIFIED"
    assert governance["p9_status"] == "NOT_QUALIFIED"
    assert governance["vip_status"] == "NOT_QUALIFIED"
    assert governance["bug_bounty_status"] == "BLOCKED"
    assert governance["human_signoff"] is False


def test_controlled_arex_campaign_does_not_store_raw_observations():
    report = run_campaign()
    serialized = str(report)

    assert "response_body" not in serialized
    assert "Set-Cookie" not in serialized
    assert "Authorization" not in serialized
    assert "password" not in serialized.lower()
