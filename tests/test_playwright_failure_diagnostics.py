from webpent.shared.playwright_adapter import PlaywrightBrowserHandler


def _handler() -> PlaywrightBrowserHandler:
    return PlaywrightBrowserHandler(
        target_origin="http://127.0.0.1:18080",
        engagement_id="diagnostics-test-engagement",
    )


def test_blocked_http_status_has_structured_safe_diagnostics():
    result = _handler()._blocked(
        "blocked_http_status",
        status_code=403,
        operation="navigate",
    )

    assert result["handler_status"] == "blocked"
    assert result["target_backed"] is False
    assert result["replayable"] is False
    assert result["reason"] == "blocked_http_status"
    assert result["failure_code"] == "blocked_http_status"
    assert result["missing_fields"] == ["successful_http_observation"]
    assert result["diagnostic"] == {
        "failure_code": "blocked_http_status",
        "missing_fields": ["successful_http_observation"],
        "status_code": 403,
        "operation": "navigate",
    }
    assert "body" not in result
    assert "cookie" not in result
    assert "password" not in result


def test_browser_failure_reason_keeps_detail_but_has_stable_code():
    result = _handler()._blocked(
        "browser_execution_failed:TimeoutError",
        operation="validate_input",
    )

    assert result["reason"] == "browser_execution_failed:TimeoutError"
    assert result["failure_code"] == "browser_execution_failed"
    assert result["missing_fields"] == ["browser_observation"]
    assert result["diagnostic"]["status_code"] is None
    assert result["diagnostic"]["operation"] == "validate_input"


def test_missing_observation_diagnostics_remain_fail_closed():
    result = _handler()._blocked("validator_input_field_missing")

    assert result["handler_status"] == "blocked"
    assert result["target_backed"] is False
    assert result["replayable"] is False
    assert result["failure_code"] == "validator_input_field_missing"
    assert result["missing_fields"] == ["input_field"]
    assert result["diagnostic"]["status_code"] is None
    assert result["diagnostic"]["operation"] == ""


class _FakeField:
    def __init__(self, field_type, *, raises=False):
        self.field_type = field_type
        self.raises = raises

    def get_attribute(self, name):
        if self.raises:
            raise RuntimeError("field unavailable")
        assert name == "type"
        return self.field_type


def test_search_enter_fallback_is_narrowly_typed():
    assert PlaywrightBrowserHandler._is_search_field(_FakeField("search")) is True
    assert PlaywrightBrowserHandler._is_search_field(_FakeField("text")) is False
    assert PlaywrightBrowserHandler._is_search_field(_FakeField(None)) is False
    assert PlaywrightBrowserHandler._is_search_field(_FakeField("search", raises=True)) is False


def test_search_enter_fallback_does_not_reclassify_account_or_generic_forms():
    for field_type in ("password", "email", "text", "url", None):
        assert PlaywrightBrowserHandler._is_search_field(_FakeField(field_type)) is False
