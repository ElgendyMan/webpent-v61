import json
from pathlib import Path

import pytest

from webpent.cli import _promote_named_owner_profile
from webpent.cli.loaders import load_creds_file


def test_cookie_backed_profiles_keep_ownership_metadata(tmp_path: Path):
    profiles_file = tmp_path / "profiles.json"
    profiles_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "owner": {
                        "role": "owner",
                        "credentials": {"username": "owner@example.test", "password": "dummy"},
                        "cookies": {"laravel_session": "dummy-cookie"},
                        "owned_object_ids": ["1"],
                    },
                    "foreign": {
                        "role": "foreign",
                        "cookies": {"laravel_session": "dummy-foreign-cookie"},
                        "owned_object_ids": ["2"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    profiles = load_creds_file(profiles_file)
    credentials, retained = _promote_named_owner_profile({}, profiles)

    assert credentials["username"] == "owner@example.test"
    assert "password" in credentials
    assert retained["owner"]["owned_object_ids"] == ["1"]
    assert retained["foreign"]["owned_object_ids"] == ["2"]
    assert retained["owner"]["cookies"]["laravel_session"] == "dummy-cookie"


def test_cookie_only_profile_is_accepted_without_credentials(tmp_path: Path):
    profiles_file = tmp_path / "cookie-only.json"
    profiles_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "foreign": {
                        "role": "foreign",
                        "cookies": {"laravel_session": "dummy-cookie"},
                        "owned_urls": ["http://127.0.0.1:8000/v1/crm/download/2"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    profiles = load_creds_file(profiles_file)

    assert profiles["foreign"]["cookies"]["laravel_session"] == "dummy-cookie"
    assert profiles["foreign"]["owned_urls"] == [
        "http://127.0.0.1:8000/v1/crm/download/2"
    ]



def test_promoted_profiles_are_deeply_isolated(tmp_path: Path):
    profiles_file = tmp_path / "isolated.json"
    profiles_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "owner": {
                        "role": "owner",
                        "credentials": {"username": "owner@example.test", "password": "dummy"},
                        "cookies": {"laravel_session": "owner-cookie"},
                        "owned_object_ids": ["1"],
                    },
                    "foreign": {
                        "role": "foreign",
                        "cookies": {"laravel_session": "foreign-cookie"},
                        "owned_object_ids": ["2"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    source_profiles = load_creds_file(profiles_file)
    _, retained = _promote_named_owner_profile({}, source_profiles)

    retained["owner"]["cookies"]["laravel_session"] = "mutated-owner-cookie"
    retained["owner"]["owned_object_ids"].append("99")

    assert source_profiles["owner"]["cookies"]["laravel_session"] == "owner-cookie"
    assert source_profiles["owner"]["owned_object_ids"] == ["1"]
    assert retained["foreign"]["cookies"]["laravel_session"] == "foreign-cookie"
    assert retained["foreign"]["owned_object_ids"] == ["2"]


def test_profiles_reject_unsupported_fields(tmp_path: Path):
    profiles_file = tmp_path / "unsupported.json"
    profiles_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "owner": {
                        "cookies": {"laravel_session": "dummy-cookie"},
                        "unsupported_runtime_control": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported fields"):
        load_creds_file(profiles_file)
