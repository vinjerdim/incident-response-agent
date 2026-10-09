"""Re-export: the scripted fake client lives in ira.testing (also used by evals)."""

from ira.testing import FakeClient, last_user_content, msg, parsed, text, tool_use

__all__ = ["FakeClient", "last_user_content", "msg", "parsed", "text", "tool_use"]
