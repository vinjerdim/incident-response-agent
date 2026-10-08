"""Runtime configuration. The model name lives here only. Override via IRA_* env vars."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IRA_", env_file=".env", extra="ignore")

    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    refusal_fallback: bool = True
    max_steps: int = Field(default=12, ge=1, le=100)
    max_tokens_total: int = Field(default=200_000, ge=1_000)
    max_tokens_per_call: int = Field(default=16_000, ge=256)
    tool_timeout_s: float = Field(default=10.0, gt=0)
    fixtures_dir: Path = Path("fixtures")
    db_path: Path = Path("ira.sqlite")
    use_fixtures: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
