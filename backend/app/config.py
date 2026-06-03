from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Cloudflare DNS Failover"
    app_env: str = "development"
    secret_key: str = "dev-secret-change-me"
    app_encryption_key: str = "dev-encryption-key-change-me"
    database_url: str = "sqlite:///./data/app.db"
    cors_origins: str = "http://localhost:8080,http://localhost:5173"
    check_interval_seconds: int = 30
    check_timeout_seconds: float = 5.0
    external_ip_sync_interval_seconds: int = 600
    no_healthy_notification_interval_seconds: int = 30 * 60
    fail_threshold: int = 5
    recovery_threshold: int = 2
    access_token_ttl_seconds: int = 7 * 24 * 60 * 60
    access_token_remember_ttl_seconds: int = 30 * 24 * 60 * 60
    login_max_failures: int = 5
    login_failure_window_seconds: int = 15 * 60
    login_lockout_seconds: int = 15 * 60

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
