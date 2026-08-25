from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "run_juice_shop_p10_full.py"


spec = importlib.util.spec_from_file_location("juice_shop_p10_full", MODULE_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_target_integrity_result_requires_available_matching_metadata() -> None:
    before = {
        "available": True,
        "container_id_digest": "sha256:container",
        "image_id_digest": "sha256:image",
        "config_image_digest": "sha256:config",
        "hostname_digest": "sha256:hostname",
    }
    after = dict(before)

    result = module.target_integrity_result(before, after)

    assert result == {
        "target_unchanged_measured": True,
        "measurement_method": "docker_inspect_immutable_metadata",
        "before_available": True,
        "after_available": True,
        "reason": "immutable_metadata_match",
    }


def test_target_integrity_result_fails_closed_on_mismatch_or_unavailable() -> None:
    before = {
        "available": True,
        "container_id_digest": "sha256:container-a",
        "image_id_digest": "sha256:image",
        "config_image_digest": "sha256:config",
        "hostname_digest": "sha256:hostname",
    }
    after = dict(before)
    after["image_id_digest"] = "sha256:image-b"

    mismatch = module.target_integrity_result(before, after)
    unavailable = module.target_integrity_result(
        {"available": False, "reason": "docker_inspect_failed"},
        after,
    )

    assert mismatch["target_unchanged_measured"] is False
    assert mismatch["reason"] == "immutable_metadata_mismatch_or_unavailable"
    assert unavailable["target_unchanged_measured"] is False
    assert unavailable["before_available"] is False
    assert unavailable["after_available"] is True


def test_target_integrity_result_contains_no_raw_docker_fields() -> None:
    result = module.target_integrity_result(
        {"available": True, "container_id": "raw-id"},
        {"available": True, "container_id": "raw-id"},
    )

    assert set(result) == {
        "target_unchanged_measured",
        "measurement_method",
        "before_available",
        "after_available",
        "reason",
    }
    assert "raw-id" not in str(result)
