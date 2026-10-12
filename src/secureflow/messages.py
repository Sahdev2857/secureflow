"""Typed, deliberately untrusted messages exchanged by workspace agents."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    EXTERNAL = "external"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Finding(BaseModel):
    guard_name: str
    category: str
    severity: Severity
    description: str
    evidence: str = "[redacted]"
    span: tuple[int, int] | None = None
    contributing_message_ids: list[str] = Field(default_factory=list)


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    sender: str
    recipient: str
    content: str
    trust: TrustLevel = TrustLevel.AGENT
    tool_calls: list[ToolCall] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GateContext(BaseModel):
    """Bounded recipient-visible history used by stateful context guards."""

    workflow_id: str
    recipient: str
    recent: list[Message] = Field(default_factory=list)
    assembled_text: str = ""
