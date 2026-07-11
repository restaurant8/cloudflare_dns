from datetime import datetime, timezone
from types import SimpleNamespace

from app.time_routing import is_time_rule_active


MONDAY = 1 << 0
SUNDAY = 1 << 6


def time_rule(**overrides):
    values = {
        "enabled": True,
        "timezone": "UTC",
        "weekdays_mask": MONDAY,
        "start_minute": 9 * 60,
        "end_minute": 17 * 60,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_regular_window_uses_inclusive_start_and_exclusive_end():
    rule = time_rule()

    assert is_time_rule_active(rule, datetime(2026, 7, 6, 9, 0)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 6, 16, 59, 59)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 6, 8, 59, 59)) is False
    assert is_time_rule_active(rule, datetime(2026, 7, 6, 17, 0)) is False


def test_cross_midnight_window_attributes_early_hours_to_start_weekday():
    rule = time_rule(start_minute=23 * 60, end_minute=2 * 60)

    assert is_time_rule_active(rule, datetime(2026, 7, 6, 23, 0)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 7, 1, 59, 59)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 7, 2, 0)) is False
    assert is_time_rule_active(rule, datetime(2026, 7, 7, 23, 30)) is False


def test_cross_midnight_window_wraps_sunday_into_monday():
    rule = time_rule(weekdays_mask=SUNDAY, start_minute=23 * 60, end_minute=2 * 60)

    assert is_time_rule_active(rule, datetime(2026, 7, 5, 23, 30)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 6, 1, 30)) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 5, 1, 30)) is False


def test_timezone_conversion_accepts_naive_utc_and_aware_datetimes():
    rule = time_rule(timezone="Asia/Tokyo", start_minute=9 * 60, end_minute=10 * 60)
    naive_utc = datetime(2026, 7, 6, 0, 30)
    aware_utc = datetime(2026, 7, 6, 0, 30, tzinfo=timezone.utc)

    assert is_time_rule_active(rule, naive_utc) is True
    assert is_time_rule_active(rule, aware_utc) is True
    assert is_time_rule_active(rule, datetime(2026, 7, 6, 1, 0, tzinfo=timezone.utc)) is False


def test_disabled_or_zero_length_rule_is_inactive():
    assert is_time_rule_active(time_rule(enabled=False), datetime(2026, 7, 6, 12, 0)) is False
    assert is_time_rule_active(time_rule(start_minute=60, end_minute=60), datetime(2026, 7, 6, 1, 0)) is False


def test_invalid_persisted_timezone_is_inactive_instead_of_raising():
    assert is_time_rule_active(time_rule(timezone="Mars/Olympus_Mons"), datetime(2026, 7, 6, 12, 0)) is False
