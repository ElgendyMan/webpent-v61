from __future__ import annotations

import json

from scripts import build_release_manifest as manifest


def test_live_artifact_is_marked_historical_in_release_qualification(monkeypatch, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "waptlab_live_smoke_2cb9024.json").write_text(
        json.dumps(
            {
                "live_qualification": True,
                "target_contacted": True,
                "waptlab_modified": False,
                "qualification_status": "not_qualified",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(manifest, "PROJECT_ROOT", tmp_path)

    result = manifest._qualification()

    assert result["artifact_scope"] == "historical_live_artifact"
    assert result["live_qualification"] is True
    assert result["status"] == "not_qualified"


def test_offline_regression_artifact_is_not_live(monkeypatch, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "waptlab_regression.json").write_text(
        json.dumps(
            {
                "live_qualification": False,
                "target_contacted": False,
                "waptlab_modified": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(manifest, "PROJECT_ROOT", tmp_path)

    result = manifest._qualification()

    assert result["artifact_scope"] == "offline_regression_artifact"
    assert result["live_qualification"] is False
    assert result["target_contacted"] is False
