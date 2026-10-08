import pytest
from pydantic import ValidationError

from ira.config import Settings


def test_defaults_are_bounded():
    s = Settings(_env_file=None)
    assert s.max_steps >= 1
    assert s.tool_timeout_s > 0
    assert s.use_fixtures is True
    assert s.model


def test_env_override(monkeypatch):
    monkeypatch.setenv("IRA_MODEL", "some-other-model")
    monkeypatch.setenv("IRA_MAX_STEPS", "3")
    s = Settings(_env_file=None)
    assert s.model == "some-other-model"
    assert s.max_steps == 3


def test_rejects_unbounded_steps(monkeypatch):
    monkeypatch.setenv("IRA_MAX_STEPS", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
