from __future__ import annotations

import zipfile

from scripts.build_source_archive import archive_members, build_archive


def test_archive_members_exclude_runtime_and_historical_evidence():
    names = [name for _, name in archive_members()]

    assert names == sorted(names)
    assert all("/artifacts/" not in name for name in names)
    assert all("/docs/evidence/" not in name for name in names)
    assert all(not name.endswith(".log") for name in names)
    assert all(not name.endswith((".db", ".sqlite", ".sqlite3")) for name in names)
    assert "webpent-v61/src/webpent/shared/tool_adapters.py" in names
    assert "webpent-v61/docs/release_manifest.json" in names


def test_build_archive_is_deterministic_for_same_source(tmp_path):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    build_archive(first)
    build_archive(second)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.testzip() is None
        assert all(not name.endswith(".log") for name in archive.namelist())
