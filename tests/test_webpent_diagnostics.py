from __future__ import annotations

import argparse
import json

from scripts import webpent_diagnostics as diagnostics

REQUIRED_FINDING_FIELDS = {
    "check_id",
    "component",
    "status",
    "severity",
    "observed",
    "expected",
    "likely_cause",
    "remediation",
    "retryability",
    "evidence",
    "network_access",
}


def _args(**overrides):
    values = {
        "network_checks": False,
        "docker_config": False,
        "ports": [],
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_default_report_is_read_only_and_schema_complete():
    report = diagnostics.build_report(_args())

    assert report["destructive_actions_performed"] is False
    assert report["llm_probe_performed"] is False
    assert report["network_checks_enabled"] is False
    assert report["findings"]
    assert all(set(item) >= REQUIRED_FINDING_FIELDS for item in report["findings"])
    assert all(item["network_access"] is False for item in report["findings"])


def test_json_report_is_serializable_and_does_not_include_secret_values(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret-must-not-appear")
    report = diagnostics.build_report(_args())
    encoded = json.dumps(report)

    assert "test-secret-must-not-appear" not in encoded
    assert "provider_names_only" in encoded or "values_redacted" in encoded


def test_network_checks_are_explicitly_marked_when_disabled():
    report = diagnostics.build_report(_args(ports=[3000, 8000]))
    port_items = [item for item in report["findings"] if item["check_id"].startswith("port.")]

    assert len(port_items) == 2
    assert all(item["status"] == "SKIPPED" for item in port_items)
    assert all(item["network_access"] is False for item in port_items)


def test_toolchain_contract_reports_pinned_versions_and_template_manifest(
    monkeypatch,
):
    monkeypatch.setattr(
        diagnostics,
        "_toolchain_command",
        lambda name: ([0, f"{diagnostics.TOOLCHAIN_CONTRACT[name]['expected_version']}\n", ""]),
    )
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        diagnostics,
        "_read_nuclei_template_manifest",
        lambda: {
            "schema_version": "nuclei-template-manifest-v1",
            "version": "v3.9.0",
            "digest": "a" * 64,
            "file_count": 1,
        },
    )

    items = diagnostics.check_toolchain()

    assert {item.check_id for item in items} >= {
        "toolchain.nuclei",
        "toolchain.templates",
    }
    assert all(item.status == "PASS" for item in items)
    template = next(item for item in items if item.check_id == "toolchain.templates")
    assert template.evidence["digest"] == "a" * 64


def test_toolchain_template_manifest_is_fail_closed_when_missing(monkeypatch):
    monkeypatch.setattr(diagnostics, "_read_nuclei_template_manifest", lambda: None)

    items = diagnostics.check_toolchain()

    template = next(item for item in items if item.check_id == "toolchain.templates")
    assert template.status == "BLOCKED"
    assert template.severity == "error"
    assert template.evidence["manifest_present"] is False


def test_human_renderer_surfaces_remediation_without_secret_values():
    report = {
        "timestamp": "2026-08-22T00:00:00Z",
        "project_root": "/tmp/project",
        "summary": {"PASS": 0, "WARN": 1, "BLOCKED": 0, "SKIPPED": 0},
        "findings": [
            {
                "check_id": "llm.configuration",
                "status": "WARN",
                "severity": "warning",
                "observed": "no provider key detected",
                "remediation": "configure one provider through protected environment settings",
            }
        ],
    }

    rendered = diagnostics.render_human(report)
    assert "configure one provider" in rendered
    assert "API_KEY" not in rendered
