import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import User
from app.routes.ssh import create_ssh_session, read_ssh_settings, update_ssh_settings
from app.schemas import SshSettingsUpdate


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def make_user(db):
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_ssh_settings_default_to_disabled_local_upstream():
    db = make_session()
    user = make_user(db)

    settings = read_ssh_settings(user, db)

    assert settings.enabled is False
    assert settings.upstream_url == "http://127.0.0.1:8182"
    assert settings.entry_path == "/api/ssh/proxy/"


def test_ssh_settings_reject_non_local_upstream():
    db = make_session()
    user = make_user(db)

    with pytest.raises(ValidationError):
        SshSettingsUpdate(upstream_url="http://192.0.2.10:8182")

    with pytest.raises(ValidationError):
        update_ssh_settings(SshSettingsUpdate(enabled=True, upstream_url="http://example.com:8182"), user, db)


def test_ssh_session_requires_enabled_settings_and_sets_cookie():
    db = make_session()
    user = make_user(db)

    with pytest.raises(HTTPException):
        create_ssh_session(user, db)

    update_ssh_settings(SshSettingsUpdate(enabled=True, session_ttl_seconds=120), user, db)
    response = create_ssh_session(user, db)

    assert response.status_code == 200
    assert "cf_dns_ssh_session=" in response.headers["set-cookie"]
    assert "Max-Age=120" in response.headers["set-cookie"]
