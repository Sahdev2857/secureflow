from pydantic import BaseModel

from secureflow.guards.tool_call import ToolCallGuard
from secureflow.messages import Message, ToolCall
from secureflow.tools import Tool, ToolRegistry


class Args(BaseModel):
    path: str


def test_blocks_unallowlisted_and_path_escape(sandbox) -> None:
    registry = ToolRegistry(sandbox)
    registry.register(Tool("write", Args, lambda path: None), {"writer"})
    guard = ToolCallGuard(registry)
    bad_agent = Message(sender="reader", recipient="x", content="", tool_calls=[ToolCall(name="write", arguments={"path": "ok"})])
    assert guard.check(bad_agent)[0].category == "tool_not_allowed"
    bad_path = Message(sender="writer", recipient="x", content="", tool_calls=[ToolCall(name="write", arguments={"path": "../escape"})])
    assert any(f.category == "path_escape" for f in guard.check(bad_path))
