from __future__ import annotations

from webpent.config.settings import get_settings
from webpent.utils.task_crypto import (
    _derive_fernet_key,
    decrypt_credentials_from_task,
    encrypt_credentials_for_task,
)


def _reset_settings_cache() -> None:
    get_settings.cache_clear()


def test_credentials_round_trip_uses_encrypted_password(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-round-trip-secret-" + "a" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()

    original = {"username": "alice", "password": "correct horse battery staple"}
    encrypted = encrypt_credentials_for_task(original)

    assert encrypted["username"] == "alice"
    assert encrypted["password"].startswith("enc:v2:")
    assert encrypted["password"] != original["password"]
    assert decrypt_credentials_from_task(encrypted) == original


def test_wrong_key_drops_password_instead_of_continuing(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-encrypt-secret-" + "b" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    encrypted = encrypt_credentials_for_task({"username": "alice", "password": "do-not-leak-this"})

    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-wrong-secret-" + "c" * 32)
    _reset_settings_cache()
    decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["username"] == "alice"
    assert decrypted["password"] == ""


def test_corrupt_ciphertext_drops_password(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-corrupt-secret-" + "d" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    encrypted = encrypt_credentials_for_task(
        {"username": "alice", "password": "do-not-leak-this-either"}
    )
    encrypted["password"] = encrypted["password"][:-4] + "xxxx"

    decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["username"] == "alice"
    assert decrypted["password"] == ""


def test_decryption_failure_log_does_not_include_password(monkeypatch, caplog) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-log-secret-" + "e" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    secret_password = "super-secret-password-that-must-not-be-logged"
    encrypted = encrypt_credentials_for_task({"username": "alice", "password": secret_password})
    encrypted["password"] = "enc:v2:not-a-valid-salt:not-a-valid-token"

    with caplog.at_level("ERROR"):
        decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["password"] == ""
    assert secret_password not in caplog.text


def test_legacy_v1_envelope_remains_readable_during_rotation(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    old_secret = "p1-old-secret-" + "g" * 32
    new_secret = "p1-new-secret-" + "h" * 32
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", new_secret)
    monkeypatch.setenv("CELERY_PAYLOAD_KEY_PREVIOUS", old_secret)
    _reset_settings_cache()
    token = Fernet(_derive_fernet_key(old_secret)).encrypt(b"legacy-password").decode("ascii")

    decrypted = decrypt_credentials_from_task(
        {"username": "alice", "password": "enc:v1:" + token}
    )

    assert decrypted == {"username": "alice", "password": "legacy-password"}


def test_v2_envelopes_use_distinct_random_salts(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-salt-secret-" + "i" * 32)
    monkeypatch.delenv("CELERY_PAYLOAD_KEY_PREVIOUS", raising=False)
    _reset_settings_cache()

    first = encrypt_credentials_for_task({"password": "same-value"})["password"]
    second = encrypt_credentials_for_task({"password": "same-value"})["password"]

    assert first.startswith("enc:v2:")
    assert second.startswith("enc:v2:")
    assert first.split(":", 3)[2] != second.split(":", 3)[2]


def test_plaintext_legacy_payload_is_preserved_for_compatibility(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-legacy-secret-" + "f" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()

    credentials = {"username": "alice", "password": "legacy-password"}

    assert decrypt_credentials_from_task(credentials) == credentials
