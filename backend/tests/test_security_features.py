import pytest
from fastapi import HTTPException

from app.notifier import _decrypt_or_plaintext
from app.routes.auth import _check_login_limiter, _clear_login_failures, _record_login_failure
from app.security import encrypt_secret


def test_login_limiter_locks_after_repeated_failures():
    key = "pytest:admin"
    _clear_login_failures(key)

    for _ in range(5):
        _record_login_failure(key)

    with pytest.raises(HTTPException) as exc:
        _check_login_limiter(key)

    assert exc.value.status_code == 429
    _clear_login_failures(key)


def test_decrypt_or_plaintext_supports_encrypted_and_legacy_values():
    assert _decrypt_or_plaintext(encrypt_secret("webhook-secret")) == "webhook-secret"
    assert _decrypt_or_plaintext("legacy-secret") == "legacy-secret"
