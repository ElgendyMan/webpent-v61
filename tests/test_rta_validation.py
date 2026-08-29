from webpent.rta import (
    RtaScope,
    create_target_app,
    default_target_configs,
    run_rta_validation,
    serve_loopback,
)


def test_real_http_validation_produces_causal_results_and_redacted_proof() -> None:
    config = default_target_configs()[0]
    scope = RtaScope(campaign_id="rta-validation-test")
    app = create_target_app(config)

    with serve_loopback(app) as base_url:
        run = run_rta_validation(base_url, scope, config)

    assert len(run.results) == 7
    assert sum(result.predicted_vulnerable for result in run.results) == 7
    assert all(result.verdict == "confirmed" for result in run.results)
    assert all(result.proof and result.proof.replay_verified for result in run.results)
    assert all(observation.redacted for observation in run.observations)
    assert all(observation.request.method == "GET" for observation in run.observations)
    assert not any(run.governance.values())


def test_real_http_validation_preserves_clean_truth_on_mixed_target() -> None:
    config = default_target_configs()[2]
    scope = RtaScope(campaign_id="rta-validation-mixed-test")
    app = create_target_app(config)

    with serve_loopback(app) as base_url:
        run = run_rta_validation(base_url, scope, config)

    by_class = {result.vulnerability_class: result for result in run.results}
    assert by_class["bfla"].predicted_vulnerable is True
    assert by_class["idor"].predicted_vulnerable is False
    assert by_class["business_logic"].predicted_vulnerable is False
    assert by_class["tenant_partial_access"].predicted_vulnerable is True
    assert by_class["idor"].truth_vulnerable is False
    assert by_class["business_logic"].truth_vulnerable is False
