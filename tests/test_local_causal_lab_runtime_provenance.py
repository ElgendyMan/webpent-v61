from dataclasses import replace
from pathlib import Path

from webpent.adapters.crapi.option_b import (
    CRAPI_RUNTIME_IMAGE_DIGESTS,
    CRAPI_SOURCE_FILES,
    CRAPI_SOURCE_REVISION,
)
from webpent.adapters.local_causal_lab.runtime_provenance import (
    RuntimeProvenance,
    readiness_check,
    source_digest_check,
)
from webpent.adapters.webgoat.option_b import (
    WEBGOAT_RUNTIME_DIGEST,
    WEBGOAT_RUNTIME_DIGEST_STATUS,
    WEBGOAT_SOURCE_FILES,
    WEBGOAT_SOURCE_REVISION,
)

CRAPI_ROOT = Path("/tmp/crapi-source")
WEBGOAT_ROOT = Path("/tmp/webgoat-source")


def _provenance_for_webgoat() -> RuntimeProvenance:
    return RuntimeProvenance(
        target_id="owasp_webgoat",
        source_revision=WEBGOAT_SOURCE_REVISION,
        source_files=tuple(
            (name, item["path"], item["sha256"])
            for name, item in WEBGOAT_SOURCE_FILES.items()
        ),
        runtime_digest_status=WEBGOAT_RUNTIME_DIGEST_STATUS,
        runtime_digest=WEBGOAT_RUNTIME_DIGEST,
        toolchain_digest="2a41998843f23adf80ba13b1e2572a55f7a642d630c640ac561b9de8e3b2b660",
        service_alignment_status="not_attested",
    )


def _provenance_for_crapi() -> RuntimeProvenance:
    return RuntimeProvenance(
        target_id="crapi",
        source_revision=CRAPI_SOURCE_REVISION,
        source_files=tuple(
            (name, item["path"], item["sha256"])
            for name, item in CRAPI_SOURCE_FILES.items()
        ),
        runtime_digest_status="pinned",
        runtime_digest=CRAPI_RUNTIME_IMAGE_DIGESTS[0][1].removeprefix("sha256:"),
        service_alignment_status="attested",
        image_digests=CRAPI_RUNTIME_IMAGE_DIGESTS,
    )


def test_webgoat_source_pin_matches_but_service_alignment_blocks() -> None:
    provenance = _provenance_for_webgoat()
    assert provenance.validate() == ()
    result = readiness_check(provenance, WEBGOAT_ROOT)
    assert result["source"]["all_match"] is True
    assert result["status"] == "blocked"
    assert "service_artifact_alignment_not_attested" in result["errors"]


def test_crapi_source_and_runtime_pins_are_attested() -> None:
    provenance = _provenance_for_crapi()
    assert provenance.validate() == ()
    result = readiness_check(provenance, CRAPI_ROOT)
    assert result["source"]["all_match"] is True
    assert result["status"] == "ready"
    assert result["errors"] == []


def test_source_digest_drift_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("changed", encoding="utf-8")
    provenance = RuntimeProvenance(
        target_id="test",
        source_revision="a" * 40,
        source_files=(("source", "source.txt", "0" * 64),),
        runtime_digest_status="pinned",
        runtime_digest="1" * 64,
        service_alignment_status="attested",
    )
    result = source_digest_check(provenance, tmp_path)
    assert result["all_match"] is False
    assert readiness_check(provenance, tmp_path)["status"] == "blocked"


def test_unpinned_runtime_and_unattested_service_are_blocked() -> None:
    provenance = _provenance_for_crapi()
    invalid = replace(
        provenance,
        runtime_digest_status="runtime_digest_unavailable",
        runtime_digest=None,
        service_alignment_status="not_attested",
    )
    result = readiness_check(invalid, CRAPI_ROOT)
    assert result["status"] == "blocked"
    assert "runtime_digest_not_pinned" in result["errors"]
    assert "service_artifact_alignment_not_attested" in result["errors"]
