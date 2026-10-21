from functools import lru_cache
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE = {"", "change-me", "changeme", "replace-with-long-random-string"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "development"
    SERVICE_ROLE: str = "api"  # "api" | "worker" (worker does not send email / serve users)
    APP_SECRET_KEY: str = "change-me"
    SESSION_SECRET: str = "change-me"
    DATABASE_URL: str = "sqlite:///./dev.db"
    REDIS_URL: str = ""
    FRONTEND_URL: str = "http://localhost:5173"
    BACKEND_URL: str = "http://localhost:8000"
    CORS_ORIGINS: str = "http://localhost:5173"

    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = ""
    EMAIL_PROVIDER: str = "resend"  # "resend" | "console" (development only)

    OTP_EXPIRY_SECONDS: int = 300
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_ATTEMPTS: int = 5
    OTP_MAX_RESENDS: int = 5
    PASSWORD_RESET_EXPIRY_SECONDS: int = 900
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REMEMBER_ME_REFRESH_DAYS: int = 30

    # "limit/window_seconds" per bucket
    RATE_LIMIT_REGISTER: str = "5/3600"
    RATE_LIMIT_LOGIN: str = "10/300"
    RATE_LIMIT_OTP_VERIFY: str = "10/300"
    RATE_LIMIT_OTP_RESEND: str = "5/3600"
    RATE_LIMIT_FORGOT: str = "5/3600"

    ARTIFACT_STORAGE_BACKEND: str = "local"  # local | s3
    ARTIFACT_STORAGE_PATH: str = "./artifacts"
    S3_BUCKET: str = ""
    S3_ENDPOINT_URL: str = ""
    S3_ACCESS_KEY_ID: str = ""
    S3_SECRET_ACCESS_KEY: str = ""
    S3_REGION: str = "auto"

    MAX_UPLOAD_MB: int = 50
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    FIRST_ADMIN_EMAIL: str = ""

    @property
    def is_prod(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @model_validator(mode="after")
    def _validate(self):
        if self.is_prod:
            problems = []
            if self.APP_SECRET_KEY in INSECURE or len(self.APP_SECRET_KEY) < 32:
                problems.append("APP_SECRET_KEY must be set (>=32 chars)")
            if self.SESSION_SECRET in INSECURE or len(self.SESSION_SECRET) < 32:
                problems.append("SESSION_SECRET must be set (>=32 chars)")
            if self.DATABASE_URL.startswith("sqlite"):
                problems.append("DATABASE_URL must be PostgreSQL in production")
            if self.SERVICE_ROLE != "worker":
                if self.EMAIL_PROVIDER != "resend":
                    problems.append("EMAIL_PROVIDER must be 'resend' in production")
                if not self.RESEND_API_KEY:
                    problems.append("RESEND_API_KEY is required")
                if not self.EMAIL_FROM:
                    problems.append("EMAIL_FROM is required")
                if not self.FRONTEND_URL.startswith("https://"):
                    problems.append("FRONTEND_URL must be https in production")
                if "*" in self.cors_list:
                    problems.append("CORS_ORIGINS must not contain '*'")
            if self.ARTIFACT_STORAGE_BACKEND == "s3" and not (self.S3_BUCKET and self.S3_ACCESS_KEY_ID):
                problems.append("S3 settings required when ARTIFACT_STORAGE_BACKEND=s3")
            if problems:
                raise ValueError("Invalid production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
