from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_name: str = "TehranNetwork"
    app_short_name: str = "TehranNetwork"
    app_base_url: str = "https://tunnel.softarg.ir"
    app_secret_key: str
    jwt_secret_key: str
    jwt_expire_minutes: int = 30

    database_url: str
    redis_url: str

    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None
    bootstrap_admin_email: str | None = None

    telegram_bot_token: str | None = None
    telegram_bot_enabled: bool = False
    bot_internal_api_key: str | None = None

    billing_mode: str = "development"
    payments_enabled: bool = False
    default_currency: str = "USDT"
    secondary_currency: str = "IRT"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
