from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_SECRET_KEY = "dev-secret-change-me"
DEFAULT_ENCRYPTION_KEY = "dev-encryption-key-change-me"


class Settings(BaseSettings):
    app_name: str = "Cloudflare DNS Failover"
    app_env: str = "development"
    secret_key: str = DEFAULT_SECRET_KEY
    app_encryption_key: str = DEFAULT_ENCRYPTION_KEY
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
    login_lockout_enabled: int = 1
    login_max_failures: int = 5
    login_failure_window_seconds: int = 15 * 60
    login_lockout_seconds: int = 15 * 60
    cloudflare_access_enabled: int = 0
    # When set, Cloudflare Access JWTs are cryptographically verified against the
    # team's JWKS. Leave empty to fall back to the legacy header-presence check.
    cloudflare_access_team_domain: str = ""
    cloudflare_access_aud: str = ""

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in {"production", "prod"}

    def check_production_secrets(self) -> None:
        """Refuse to run in production with the built-in placeholder secrets.

        With the default keys, access tokens are forgeable and stored Cloudflare /
        Telegram tokens are decryptable with a publicly known key.
        """
        if not self.is_production:
            return
        weak = []
        if self.secret_key == DEFAULT_SECRET_KEY:
            weak.append("SECRET_KEY")
        if self.app_encryption_key == DEFAULT_ENCRYPTION_KEY:
            weak.append("APP_ENCRYPTION_KEY")
        if weak:
            raise RuntimeError(
                "拒绝在 APP_ENV=production 下使用默认密钥，请在 .env 中设置："
                + "、".join(weak)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
