from __future__ import annotations

from uuid import uuid4

from webpent.agents.validator.active_checks import _csrf_header_from_cookies
from webpent.memory.db import DatabaseManager
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.reporter.export import build_report_data


def _finding() -> Finding:
    return Finding(
        id=uuid4(),
        title="Form context survives persistence",
        severity=Severity.HIGH,
        description="A request-context regression fixture.",
        tool_name="validator",
        payload="probe",
        request_method="POST",
        request_data={"rows": "1", "db": "customers"},
        target_param="rows",
        url="http://127.0.0.1:8000/crm/export",
        confidence=Confidence.TENTATIVE,
        vuln_class=VulnClass.SSTI,
    )


def test_csrf_header_decodes_laravel_cookie_without_accepting_unrelated_cookies() -> None:
    assert _csrf_header_from_cookies({"XSRF-TOKEN": "abc%2F123"}) == "abc/123"
    assert _csrf_header_from_cookies({"laravel_session": "opaque"}) is None
    assert _csrf_header_from_cookies(None) is None


def test_report_exports_request_context_without_promoting_finding() -> None:
    finding = _finding()

    report = build_report_data("http://127.0.0.1:8000", [finding])

    exported = report["findings"][0]
    assert exported["request_method"] == "POST"
    assert exported["request_data"] == {"rows": "1", "db": "customers"}
    assert exported["target_param"] == "rows"
    assert exported["confidence_level"] == "Pending"
    assert report["confirmed_count"] == 0


def test_db_round_trip_preserves_request_context(tmp_path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'findings.db'}")
    original = _finding()

    db.save_finding(original)
    loaded = db.get_finding(original.id)

    assert loaded is not None
    assert loaded.request_method == "POST"
    assert loaded.request_data == {"rows": "1", "db": "customers"}
    assert loaded.target_param == "rows"
    assert loaded.confidence_level == "Pending"


def test_db_round_trip_keeps_legacy_defaults(tmp_path) -> None:
    db = DatabaseManager(f"sqlite:///{tmp_path / 'legacy-compatible.db'}")
    original = Finding(
        id=uuid4(),
        title="Legacy shape",
        severity=Severity.LOW,
        description="No explicit request context.",
        tool_name="legacy",
        url="http://target/legacy",
        confidence=Confidence.TENTATIVE,
        vuln_class=VulnClass.UNKNOWN,
    )

    db.save_finding(original)
    loaded = db.get_finding(original.id)

    assert loaded is not None
    assert loaded.request_method == "GET"
    assert loaded.request_data == {}
    assert loaded.target_param is None
