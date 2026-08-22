from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from webpent.graph.checkpoints import get_checkpointer
from webpent.memory.db import get_db_manager
from webpent.memory.vectorstore import get_vector_store_manager
from webpent.models.findings import Finding, Severity
from webpent.shared.target_workspace import build_target_workspace
from webpent.shared.target_workspace_context import (
    activate_target_workspace,
    get_active_target_workspace,
)


def _workspace_pair(tmp_path: Path):
    settings = SimpleNamespace(target_workspace_root=tmp_path)
    workspace_a = build_target_workspace(
        settings,
        target_origin="https://target-a.example.test/app",
        client_id="client-a",
        engagement_id="engagement-a",
    ).ensure()
    workspace_b = build_target_workspace(
        settings,
        target_origin="https://target-b.example.test/app",
        client_id="client-b",
        engagement_id="engagement-b",
    ).ensure()
    return workspace_a, workspace_b


def _finding(thread_id: str) -> Finding:
    return Finding(
        title="Target-scoped test finding",
        severity=Severity.MEDIUM,
        description="Synthetic persistence record used only by isolation tests.",
        tool_name="isolation-test",
        url=f"https://{thread_id}.example.test/",
        thread_id=thread_id,
    )


def test_target_workspaces_have_distinct_storage_paths(tmp_path: Path) -> None:
    workspace_a, workspace_b = _workspace_pair(tmp_path)

    assert workspace_a.root != workspace_b.root
    assert workspace_a.database_url != workspace_b.database_url
    assert workspace_a.sessions_database_path != workspace_b.sessions_database_path
    assert workspace_a.chroma_path != workspace_b.chroma_path
    assert workspace_a.findings_ledger_path != workspace_b.findings_ledger_path

    with activate_target_workspace(workspace_a):
        assert get_active_target_workspace() == workspace_a
        db_a = get_db_manager()
    with activate_target_workspace(workspace_b):
        assert get_active_target_workspace() == workspace_b
        db_b = get_db_manager()

    assert Path(db_a._db_path()).resolve() == (
        workspace_a.databases_dir / "webpent.sqlite3"
    ).resolve()
    assert Path(db_b._db_path()).resolve() == (
        workspace_b.databases_dir / "webpent.sqlite3"
    ).resolve()
    assert db_a is not db_b
    assert get_active_target_workspace() is None


def test_findings_written_to_target_a_are_not_visible_from_target_b(tmp_path: Path) -> None:
    workspace_a, workspace_b = _workspace_pair(tmp_path)
    finding_a = _finding("thread-a")

    with activate_target_workspace(workspace_a):
        db_a = get_db_manager()
        db_a.init_db()
        db_a.save_finding(finding_a)
        assert [item.id for item in db_a.get_findings_by_threads(["thread-a"])] == [finding_a.id]

    with activate_target_workspace(workspace_b):
        db_b = get_db_manager()
        db_b.init_db()
        assert db_b.get_findings_by_threads(["thread-a"]) == []
        assert db_b.get_findings_by_threads(["thread-b"]) == []

    assert (workspace_a.databases_dir / "webpent.sqlite3").exists()
    assert (workspace_b.databases_dir / "webpent.sqlite3").exists()
    assert (workspace_a.databases_dir / "webpent.sqlite3").read_bytes() != (
        workspace_b.databases_dir / "webpent.sqlite3"
    ).read_bytes()


def test_rag_manager_is_scoped_by_active_target_path(tmp_path: Path) -> None:
    workspace_a, workspace_b = _workspace_pair(tmp_path)

    with activate_target_workspace(workspace_a):
        rag_a = get_vector_store_manager()
    with activate_target_workspace(workspace_b):
        rag_b = get_vector_store_manager()

    assert rag_a is not rag_b
    assert Path(rag_a._persist_path).resolve() == workspace_a.chroma_path.resolve()
    assert Path(rag_b._persist_path).resolve() == workspace_b.chroma_path.resolve()
    assert Path(rag_a._persist_path).resolve() != Path(rag_b._persist_path).resolve()


def test_checkpointer_uses_active_target_sessions_database(tmp_path: Path) -> None:
    workspace_a, workspace_b = _workspace_pair(tmp_path)

    with activate_target_workspace(workspace_a), get_checkpointer() as checkpointer_a:
        assert workspace_a.sessions_database_path.exists()
        conn_a = getattr(checkpointer_a, "conn", None)
        if conn_a is not None:
            database_path_a = Path(conn_a.execute("PRAGMA database_list").fetchone()[2])
            assert database_path_a.resolve() == workspace_a.sessions_database_path.resolve()

    with activate_target_workspace(workspace_b), get_checkpointer() as checkpointer_b:
        assert workspace_b.sessions_database_path.exists()
        conn_b = getattr(checkpointer_b, "conn", None)
        if conn_b is not None:
            database_path_b = Path(conn_b.execute("PRAGMA database_list").fetchone()[2])
            assert database_path_b.resolve() == workspace_b.sessions_database_path.resolve()

    assert workspace_a.sessions_database_path != workspace_b.sessions_database_path
    assert workspace_a.sessions_database_path.exists()
    assert workspace_b.sessions_database_path.exists()


def test_concurrent_target_workspaces_keep_storage_and_checkpoint_paths_isolated(
    tmp_path: Path,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    workspace_a, workspace_b = _workspace_pair(tmp_path)
    workspaces = (workspace_a, workspace_b)

    def write_target(index: int) -> dict[str, object]:
        workspace = workspaces[index]
        thread_id = f"parallel-{index}"
        with activate_target_workspace(workspace):
            db = get_db_manager()
            db.init_db()
            finding = _finding(thread_id)
            db.save_finding(finding)
            workspace.reports_dir.joinpath("report.json").write_text(
                f'{{"thread_id": "{thread_id}"}}', encoding="utf-8"
            )
            workspace.artifacts_dir.joinpath("marker.txt").write_text(
                thread_id, encoding="utf-8"
            )
            with get_checkpointer() as checkpointer:
                connection = getattr(checkpointer, "conn", None)
                checkpoint_path = ""
                if connection is not None:
                    checkpoint_path = str(
                        connection.execute("PRAGMA database_list").fetchone()[2]
                    )
            return {
                "workspace_id": get_active_target_workspace().workspace_id,
                "finding_ids": [
                    item.id for item in db.get_findings_by_threads([thread_id])
                ],
                "checkpoint_path": checkpoint_path,
                "report": workspace.reports_dir.joinpath("report.json").read_text(
                    encoding="utf-8"
                ),
                "artifact": workspace.artifacts_dir.joinpath("marker.txt").read_text(
                    encoding="utf-8"
                ),
            }

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(write_target, range(2)))

    assert [result["workspace_id"] for result in results] == [
        workspace_a.workspace_id,
        workspace_b.workspace_id,
    ]
    assert all(result["finding_ids"] for result in results)
    assert results[0]["finding_ids"] != results[1]["finding_ids"]
    assert results[0]["checkpoint_path"] == str(workspace_a.sessions_database_path)
    assert results[1]["checkpoint_path"] == str(workspace_b.sessions_database_path)
    assert results[0]["report"] != results[1]["report"]
    assert results[0]["artifact"] != results[1]["artifact"]
    assert get_active_target_workspace() is None


def test_resume_workspace_descriptor_round_trip_is_target_scoped(tmp_path: Path) -> None:
    workspace_a, _workspace_b = _workspace_pair(tmp_path)
    descriptor = workspace_a.as_dict()
    assert "cookies" not in descriptor
    assert "credentials" not in descriptor
    assert "live_handle" not in descriptor

    resumed = build_target_workspace(
        SimpleNamespace(target_workspace_root=tmp_path),
        target_origin=descriptor["target_origin"],
        client_id=descriptor["client_id"],
        engagement_id=descriptor["engagement_id"],
    ).ensure()

    assert resumed.workspace_id == workspace_a.workspace_id
    assert resumed.reports_dir == workspace_a.reports_dir
    assert resumed.artifacts_dir == workspace_a.artifacts_dir
    assert resumed.sessions_database_path == workspace_a.sessions_database_path
    assert resumed.chroma_path == workspace_a.chroma_path
    assert resumed.findings_ledger_path == workspace_a.findings_ledger_path
