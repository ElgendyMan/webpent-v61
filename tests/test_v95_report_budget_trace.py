from webpent.reporter.export import build_report_data


def test_budget_trace_is_reported_without_secrets() -> None:
    report = build_report_data(
        "https://target.test",
        [],
        campaign_ledger={
            "llm_budget_trace": [
                {"allowed": False, "reason": "budget:llm_exhausted"}
            ]
        },
    )

    assert report["llm_budget_trace"] == [
        {"allowed": False, "reason": "budget:llm_exhausted"}
    ]
    assert "password" not in str(report["llm_budget_trace"]).lower()
