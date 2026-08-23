"""Configuration safety contracts for the bbscout bridge."""

import pytest

from webpent.config.settings import Settings


def test_bbscout_defaults_are_offline_and_read_only() -> None:
    settings = Settings()

    assert settings.bbscout_enabled is False
    assert settings.bbscout_mode == "offline"
    assert settings.bbscout_require_verified_signature is True
    assert settings.bbscout_browser_enabled is False
    assert settings.bbscout_browser_read_only is True
    assert settings.bbscout_signup_enabled is False
    assert settings.bbscout_provider_submission_enabled is False


def test_bbscout_environment_aliases_are_loaded() -> None:
    settings = Settings(
        BBSCOUT_ENABLED=True,
        BBSCOUT_MODE="live",
        BBSCOUT_ALLOWED_PROVIDER_IDS="provider-a,provider-b",
        BBSCOUT_ALLOWED_PROGRAM_IDS="program-a",
    )

    assert settings.bbscout_enabled is True
    assert settings.bbscout_mode == "live"
    assert settings.bbscout_allowed_provider_ids == "provider-a,provider-b"
    assert settings.bbscout_allowed_program_ids == "program-a"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bbscout_mode", "unsupported", "bbscout_mode"),
        ("bbscout_signup_enabled", True, "signup"),
        ("bbscout_provider_submission_enabled", True, "submission"),
        ("bbscout_browser_enabled", True, "read-only"),
    ],
)
def test_bbscout_unsafe_configuration_fails_closed(
    field: str, value: object, message: str
) -> None:
    values = {field: value}
    if field == "bbscout_browser_enabled":
        values["bbscout_browser_read_only"] = False
    with pytest.raises(ValueError, match=message):
        Settings(**values)


def test_bbscout_live_requires_verified_signature() -> None:
    with pytest.raises(ValueError, match="verified detached signatures"):
        Settings(bbscout_mode="live", bbscout_require_verified_signature=False)
