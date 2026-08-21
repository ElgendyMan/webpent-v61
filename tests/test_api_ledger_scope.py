from __future__ import annotations

from types import SimpleNamespace

import pytest


class _LedgerSpy:
    calls: list[dict[str, object]] = []

    def __init__(self, _path: str) -> None:
        pass

    def get(
        self,
        engagement_id: str,
        *,
        owner_username: str | None = None,
        client_id: str | None = None,
    ) -> list[object]:
        self.calls.append(
            {
                "engagement_id": engagement_id,
                "owner_username": owner_username,
                "client_id": client_id,
            }
        )
        return []


@pytest.fixture
def scoped_api(monkeypatch):
    import webpent.api.app as app_mod

    _LedgerSpy.calls = []
    record = {
        "engagement_id": "eng-scope",
        "owner_username": "alice",
        "client_id": "tenant-a",
    }
    monkeypatch.setattr(app_mod, "_authorize_scan_resource", lambda _thread, _user: record)
    monkeypatch.setattr(
        app_mod,
        "get_thread_ids_by_engagement_id",
        lambda *_args, **_kwargs: ["thread-scope"],
    )
    monkeypatch.setattr(
        app_mod,
        "get_db_manager",
        lambda: SimpleNamespace(get_findings_by_threads=lambda _threads: []),
    )
    monkeypatch.setattr(
        app_mod,
        "get_settings",
        lambda: SimpleNamespace(findings_ledger_path="/tmp/test-ledger.sqlite3"),
    )
    monkeypatch.setattr(app_mod, "PersistentFindingLedger", _LedgerSpy)
    return app_mod, SimpleNamespace(username="alice", role="operator")


def test_findings_endpoint_reads_the_authorized_ledger_scope(scoped_api) -> None:
    app_mod, user = scoped_api

    response = app_mod.get_findings("thread-scope", user=user)

    assert response.count == 0
    assert _LedgerSpy.calls == [
        {
            "engagement_id": "eng-scope",
            "owner_username": "alice",
            "client_id": "tenant-a",
        }
    ]


def test_risk_summary_reads_the_authorized_ledger_scope(scoped_api) -> None:
    app_mod, user = scoped_api

    summary = app_mod.get_risk_summary("thread-scope", user=user)

    assert summary["total_findings"] == 0
    assert _LedgerSpy.calls == [
        {
            "engagement_id": "eng-scope",
            "owner_username": "alice",
            "client_id": "tenant-a",
        }
    ]


def test_ledger_scope_is_not_optional_at_the_endpoint_boundary() -> None:
    import inspect

    import webpent.api.app as app_mod

    source = inspect.getsource(app_mod.get_findings)
    risk_source = inspect.getsource(app_mod.get_risk_summary)
    assert "owner_username=" in source
    assert "client_id=" in source
    assert "owner_username=" in risk_source
    assert "client_id=" in risk_source
