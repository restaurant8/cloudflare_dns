import json
import time

import pytest
from fastapi import HTTPException

from app.notifier import _decrypt_or_plaintext
from app.routes.auth import _check_login_limiter, _clear_login_failures, _record_login_failure
from app.security import _b64url_decode, create_access_token, encrypt_secret


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


def test_create_access_token_accepts_custom_ttl():
    token = create_access_token(1, ttl_seconds=1234)
    encoded, _ = token.split(".", 1)
    payload = json.loads(_b64url_decode(encoded))

    assert payload["sub"] == "1"
    assert 1200 <= payload["exp"] - int(time.time()) <= 1234
