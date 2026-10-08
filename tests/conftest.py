from pathlib import Path

import pytest

from ira.config import Settings

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, fixtures_dir=FIXTURES, tool_timeout_s=2.0)
