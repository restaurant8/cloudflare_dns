import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.integrations import set_setting
from app.models import User
from app.routes.settings import read_system_settings, update_system_settings
from app.runtime_settings import get_runtime_settings, invalidate_runtime_settings_cache, update_runtime_settings
from app.schemas import SystemSettingsUpdate


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def test_runtime_settings_override_defaults():
    db = make_session()

    settings = update_runtime_settings(
        db,
        {
            "check_interval_seconds": 45,
            "check_timeout_seconds": 3.5,
            "fail_threshold": 4,
        },
    )
    db.commit()

    assert settings.check_interval_seconds == 45
    assert settings.check_timeout_seconds == 3.5
    assert settings.fail_threshold == 4
    assert get_runtime_settings(db).check_interval_seconds == 45


def test_runtime_settings_are_cached_per_session_and_invalidated_on_update():
    db = make_session()

    initial = get_runtime_settings(db)

    assert get_runtime_settings(db) is initial

    updated = update_runtime_settings(db, {"check_interval_seconds": 45})

    assert updated is not initial
    assert get_runtime_settings(db) is updated
    assert updated.check_interval_seconds == 45


def test_generic_setting_writer_invalidates_runtime_cache_for_owned_key():
    db = make_session()
    initial = get_runtime_settings(db)

    set_setting(db, "fail_threshold", "4")

    refreshed = get_runtime_settings(db)
    assert refreshed is not initial
    assert refreshed.fail_threshold == 4


def test_runtime_cache_invalidator_only_clears_runtime_owned_keys():
    db = make_session()
    initial = get_runtime_settings(db)

    invalidate_runtime_settings_cache(db, "azpanel.timeout_seconds")
    assert get_runtime_settings(db) is initial

    invalidate_runtime_settings_cache(db, "fail_threshold")
    assert get_runtime_settings(db) is not initial


def test_runtime_settings_reject_out_of_range_values():
    db = make_session()

    with pytest.raises(ValueError):
        update_runtime_settings(db, {"check_interval_seconds": 3})


def test_settings_route_reads_and_updates_values():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()

    updated = update_system_settings(SystemSettingsUpdate(check_interval_seconds=90, login_max_failures=8), user, db)

    assert updated.check_interval_seconds == 90
    assert updated.login_max_failures == 8
    assert read_system_settings(user, db).check_interval_seconds == 90
