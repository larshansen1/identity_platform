from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    APP_NAME: str = "Identity Platform"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/identity_platform"

    # Security
    SECRET_KEY: str = "insecure-default-secret-key-change-in-production"  # noqa: S105

    # Bootstrap Admin (Optional)
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] = None
    BOOTSTRAP_ADMIN_NAME: Optional[str] = None
    BOOTSTRAP_ADMIN_ROLES: str = "REQUESTER,APPROVER"

    # Bootstrap Approver (Optional - second admin for testing approval workflows)
    BOOTSTRAP_APPROVER_EMAIL: Optional[str] = None
    BOOTSTRAP_APPROVER_NAME: Optional[str] = None


settings = Settings()
