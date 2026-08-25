from datetime import UTC, datetime, timedelta

import pytest

from webpent.shared.target_spec import RequestBudget, TargetSpec


def auth(*, confirmed: bool = True) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "authorization_id": "auth-local-001",
        "authorized_by": "lab-owner",
        "operator": "webpent-ci",
        "permitted_test_types": ["passive", "safe-active"],
        "exclusions": ["/admin/delete"],
        "emergency_stop_contact": "lab-owner@example.test",
        "time_window_start": now.isoformat(),
        "time_window_end": (now + timedelta(hours=1)).isoformat(),
        "user_confirmed": confirmed,
    }


def spec(**overrides: object) -> TargetSpec:
    values: dict[str, object] = {
        "engagement_id": "juice-shop-local-001",
        "base_url": "http://127.0.0.1:3000/",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_ports": [3000],
        "allowed_paths": ["/"],
        "excluded_paths": ["/admin/delete"],
        "profile": "single_target_safe",
        "auth_mode": "unauthenticated",
        "allowed_schemes": ["http"],
        "max_requests": 10,
        "max_concurrency": 2,
        "requests_per_second": 2.0,
        "timeout_seconds": 10,
        "allow_private_target": True,
        "authorization": auth(),
    }
    values.update(overrides)
    return TargetSpec.model_validate(values)


def test_target_spec_rejects_unconfirmed_authorization() -> None:
    with pytest.raises(ValueError, match="user_confirmed"):
        spec(authorization=auth(confirmed=False))


def test_scope_validator_accepts_declared_target_and_rejects_redirects() -> None:
    validator = spec().scope_validator()
    assert validator.decide("http://127.0.0.1:3000/api/Challenges").allowed
    assert validator.decide("http://127.0.0.1:3001/api/Challenges").reason_code == (
        "port_not_allowed"
    )
    assert validator.validate_redirect("http://127.0.0.1:3000/admin/delete").reason_code == (
        "excluded_path"
    )
    assert validator.validate_redirect("http://localhost:3000/api").reason_code == (
        "host_not_allowed"
    )


def test_private_target_requires_explicit_opt_in() -> None:
    validator = spec(allow_private_target=False).scope_validator()
    assert validator.decide("http://127.0.0.1:3000/").reason_code == (
        "private_address_not_authorized"
    )

    assert spec().scope_validator().validate_resolved_addresses(["127.0.0.1"])


def test_scope_validator_rejects_invalid_url_and_external_host() -> None:
    validator = spec().scope_validator()
    assert validator.decide("not-a-url").reason_code == "invalid_url"
    assert validator.decide("https://example.com/").reason_code == "scheme_not_allowed"
    assert validator.decide("http://127.0.0.2:3000/").reason_code == "host_not_allowed"


def test_request_budget_stops_at_limit_and_emergency_stop_is_terminal() -> None:
    budget = RequestBudget(spec(max_requests=2))
    assert budget.consume()
    assert budget.consume()
    assert budget.exhausted
    assert not budget.consume()

    fresh = RequestBudget(spec(max_requests=2))
    fresh.emergency_stop()
    assert not fresh.consume()
    assert fresh.exhausted


def test_safe_dict_contains_declaration_only() -> None:
    payload = spec().safe_dict()
    assert payload["engagement_id"] == "juice-shop-local-001"
    assert "password" not in str(payload).lower()
    assert "payload" not in str(payload).lower()


def test_cli_target_spec_dry_run_has_no_target_io(tmp_path, capsys) -> None:
    from typer.testing import CliRunner

    from webpent.cli import app

    target_spec_path = tmp_path / "target.json"
    target_spec_path.write_text(
        TargetSpec.model_validate(spec().model_dump()).model_dump_json(),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        ["scan", "--config", str(target_spec_path), "--dry-run"],
    )
    assert result.exit_code == 0, result.stdout
    assert '"target_io_performed": false' in result.stdout
    assert "juice-shop-local-001" in result.stdout
    assert "password" not in result.stdout.lower()


def test_cli_target_spec_rejects_url_mismatch_without_io(tmp_path) -> None:
    from typer.testing import CliRunner

    from webpent.cli import app

    target_spec_path = tmp_path / "target.json"
    target_spec_path.write_text(spec().model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "http://127.0.0.1:3001/",
            "--target-spec",
            str(target_spec_path),
            "--dry-run",
        ],
    )
    assert result.exit_code == 1
    assert "does not match TargetSpec.base_url" in result.output
