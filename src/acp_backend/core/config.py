from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_env: str = Field(default=os.getenv("APP_ENV", "development"))
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./dev.db"))
    api_prefix: str = "/v1"
    rate_limit_per_minute: int = 60
    dlp_custom_patterns: List[str] = Field(default_factory=list)
    policy_path: str = Field(default=os.getenv("POLICY_PATH", "policies/default.yaml"))
    secret_salt: str = Field(default=os.getenv("SECRET_SALT", "change-me"))

    class Config:
        extra = "ignore"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
