from datetime import datetime, timezone
from typing import Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TimeRuleLike(Protocol):
    enabled: bool
    timezone: str
    weekdays_mask: int
    start_minute: int
    end_minute: int


def is_time_rule_active(rule: TimeRuleLike | None, now: datetime) -> bool:
    """Return whether ``rule`` is active at ``now``.

    Naive datetimes are interpreted as UTC because timestamps elsewhere in the
    application are stored as naive UTC.  Weekday mask bit 0 is Monday and bit 6
    is Sunday.  For a window that crosses midnight, the early-morning portion is
    attributed to the weekday on which the window started.
    """
    if rule is None or not rule.enabled:
        return False

    start_minute = int(rule.start_minute)
    end_minute = int(rule.end_minute)
    if not 0 <= start_minute < 24 * 60 or not 0 <= end_minute < 24 * 60:
        return False
    # The API rejects equal endpoints.  Keeping the pure helper defensive makes
    # a malformed persisted rule inactive rather than treating it as all-day.
    if start_minute == end_minute:
        return False

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    try:
        local_now = now.astimezone(ZoneInfo(rule.timezone))
    except (ValueError, ZoneInfoNotFoundError):
        # API validation prevents this for normal writes. Treat a malformed legacy
        # or manually edited row as inactive so one bad rule cannot stop its group.
        return False
    local_minute = local_now.hour * 60 + local_now.minute
    local_weekday = local_now.weekday()

    if start_minute < end_minute:
        window_weekday = local_weekday
        in_window = start_minute <= local_minute < end_minute
    elif local_minute >= start_minute:
        window_weekday = local_weekday
        in_window = True
    elif local_minute < end_minute:
        window_weekday = (local_weekday - 1) % 7
        in_window = True
    else:
        window_weekday = local_weekday
        in_window = False

    return in_window and bool(int(rule.weekdays_mask) & (1 << window_weekday))
