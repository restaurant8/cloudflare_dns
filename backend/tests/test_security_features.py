import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import User
from app.notifier import _decrypt_or_plaintext
from app.routes.auth import _check_login_limiter, _clear_login_failures, _record_login_failure, change_username, login
from app.runtime_settings import update_runtime_settings
from app.schemas import LoginRequest, UsernameChangeRequest
from app.security import _b64url_decode, create_access_token, encrypt_secret, hash_password


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def request(headers=None, client_host="127.0.0.1", cookies=None):
    return SimpleNamespace(headers=headers or {}, cookies=cookies or {}, client=SimpleNamespace(host=client_host))


def test_login_limiter_locks_after_repeated_failures():
    key = "pytest:admin"
    _clear_login_failures(key)

    for _ in range(5):
        _record_login_failure(key)

    with pytest.raises(HTTPException) as exc:
        _check_login_limiter(key)

    assert exc.value.status_code == 429
    _clear_login_failures(key)


def test_login_limiter_can_be_disabled():
    key = "pytest:disabled"
    _clear_login_failures(key)
    settings = SimpleNamespace(login_lockout_enabled=0, login_max_failures=1, login_failure_window_seconds=60, login_lockout_seconds=60)

    _record_login_failure(key, settings)
    _check_login_limiter(key, settings)

    _clear_login_failures(key)


def test_login_requires_cloudflare_access_when_enabled():
    db = make_session()
    user = User(username="admin", password_hash=hash_password("password123"))
    db.add(user)
    db.commit()
    update_runtime_settings(db, {"cloudflare_access_enabled": 1})
    db.commit()

    with pytest.raises(HTTPException) as exc:
        login(LoginRequest(username="admin", password="password123"), request(), db)

    assert exc.value.status_code == 403

    response = login(
        LoginRequest(username="admin", password="password123"),
        request(headers={"cf-access-authenticated-user-email": "admin@example.com", "cf-access-jwt-assertion": "jwt"}),
        db,
    )

    assert response.access_token


def test_change_username_requires_password_and_unique_name():
    db = make_session()
    user = User(username="admin", password_hash=hash_password("password123"))
    other = User(username="other", password_hash=hash_password("password123"))
    db.add_all([user, other])
    db.commit()
    db.refresh(user)

    with pytest.raises(HTTPException):
        change_username(UsernameChangeRequest(username="next-admin", current_password="wrong"), user, db)
    with pytest.raises(HTTPException):
        change_username(UsernameChangeRequest(username="other", current_password="password123"), user, db)

    updated = change_username(UsernameChangeRequest(username="next-admin", current_password="password123"), user, db)

    assert updated.username == "next-admin"


def test_decrypt_or_plaintext_supports_encrypted_and_legacy_values():
    assert _decrypt_or_plaintext(encrypt_secret("webhook-secret")) == "webhook-secret"
    assert _decrypt_or_plaintext("legacy-secret") == "legacy-secret"


def test_create_access_token_accepts_custom_ttl():
    token = create_access_token(1, ttl_seconds=1234)
    encoded, _ = token.split(".", 1)
    payload = json.loads(_b64url_decode(encoded))

    assert payload["sub"] == "1"
    assert 1200 <= payload["exp"] - int(time.time()) <= 1234
