from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .models import AppSetting


@dataclass(frozen=True)
class SettingDefinition:
    value_type: type
    minimum: int | float
    maximum: int | float


SETTING_DEFINITIONS: dict[str, SettingDefinition] = {
    "check_interval_seconds": SettingDefinition(int, 10, 3600),
    "check_timeout_seconds": SettingDefinition(float, 1.0, 60.0),
    "fail_threshold": SettingDefinition(int, 1, 20),
    "recovery_threshold": SettingDefinition(int, 1, 20),
    "no_healthy_notification_interval_seconds": SettingDefinition(int, 60, 86400),
    "external_ip_sync_interval_seconds": SettingDefinition(int, 60, 86400),
    "access_token_ttl_seconds": SettingDefinition(int, 3600, 31_536_000),
    "access_token_remember_ttl_seconds": SettingDefinition(int, 3600, 31_536_000),
    "login_lockout_enabled": SettingDefinition(int, 0, 1),
    "login_max_failures": SettingDefinition(int, 1, 100),
    "login_failure_window_seconds": SettingDefinition(int, 60, 86400),
    "login_lockout_seconds": SettingDefinition(int, 60, 86400),
    "cloudflare_access_enabled": SettingDefinition(int, 0, 1),
}


class RuntimeSettings:
    def __init__(self, values: dict[str, int | float]):
        for key, value in values.items():
            setattr(self, key, value)

    def model_dump(self) -> dict[str, int | float]:
        return {key: getattr(self, key) for key in SETTING_DEFINITIONS}


def _default_values(settings: Settings | None = None) -> dict[str, int | float]:
    source = settings or get_settings()
    return {key: getattr(source, key) for key in SETTING_DEFINITIONS}


def _coerce_setting_value(key: str, value: Any) -> int | float:
    definition = SETTING_DEFINITIONS[key]
    try:
        parsed = int(value) if definition.value_type is int else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be numeric") from exc
    if parsed < definition.minimum or parsed > definition.maximum:
        raise ValueError(f"{key} must be between {definition.minimum} and {definition.maximum}")
    return parsed


def get_runtime_settings(db: Session | None = None) -> RuntimeSettings:
    values = _default_values()
    if db is not None:
        rows = db.query(AppSetting).filter(AppSetting.key.in_(list(SETTING_DEFINITIONS))).all()
        for row in rows:
            values[row.key] = _coerce_setting_value(row.key, row.value)
    return RuntimeSettings(values)


def update_runtime_settings(db: Session, updates: dict[str, Any]) -> RuntimeSettings:
    for key, value in updates.items():
        if key not in SETTING_DEFINITIONS:
            continue
        parsed = _coerce_setting_value(key, value)
        row = db.get(AppSetting, key)
        if row is None:
            row = AppSetting(key=key, value=str(parsed))
            db.add(row)
        else:
            row.value = str(parsed)
    db.flush()
    return get_runtime_settings(db)
