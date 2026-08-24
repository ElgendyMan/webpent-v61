from dataclasses import asdict

from webpent.production import ProductionEvidence, qualify_production


def test_production_qualification_is_fail_closed_by_default() -> None:
    report = qualify_production(ProductionEvidence())

    assert report.qualified is False
    assert report.status == "not_qualified"
    assert "missing:docker_health" in report.reasons
    assert "missing:cross_process_idempotency" in report.reasons
    assert len(report.checks) == 12


def test_production_qualification_requires_explicit_all_checks() -> None:
    values = dict.fromkeys(asdict(ProductionEvidence()), True)
    values["external_target_contacted"] = False
    evidence = ProductionEvidence(**values)
    report = qualify_production(evidence)

    assert report.qualified is True
    assert report.status == "qualified"
    assert report.reasons == ()
    assert all(value for _, value in report.checks)


def test_external_target_contact_blocks_production_qualification() -> None:
    evidence = ProductionEvidence(
        **{
            **asdict(ProductionEvidence()),
            "docker_health": True,
            "redis_health": True,
            "celery_worker_health": True,
            "multi_worker_lease_contention": True,
            "crash_restart_recovery": True,
            "checkpoint_resume": True,
            "cross_process_idempotency": True,
            "secrets_externalized": True,
            "tls_enforced": True,
            "logs_redacted": True,
            "retention_policy_declared": True,
            "target_unchanged": True,
            "external_target_contacted": True,
        }
    )
    report = qualify_production(evidence)

    assert report.qualified is False
    assert "external_target_contacted_during_qualification" in report.reasons
