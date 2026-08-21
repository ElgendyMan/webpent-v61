from webpent.models.findings import Finding, Severity


def _finding_payload(evidence_bundle):
    return {
        "title": "Legacy evidence compatibility",
        "severity": Severity.MEDIUM,
        "description": "Compatibility test finding.",
        "tool_name": "test",
        "url": "http://example.test/resource/1",
        "evidence_bundle": evidence_bundle,
    }


def test_legacy_evidence_bundle_list_is_preserved_in_structured_envelope() -> None:
    legacy = [{"identity": "foreign", "status_code": 200}]

    finding = Finding.model_validate(_finding_payload(legacy))

    assert finding.evidence_bundle == {
        "type": "legacy_evidence_bundle",
        "legacy_format": True,
        "items": legacy,
    }


def test_current_evidence_bundle_dict_is_unchanged() -> None:
    current = {"bundle_id": "bundle-1", "sealed": True}

    finding = Finding.model_validate(_finding_payload(current))

    assert finding.evidence_bundle == current
