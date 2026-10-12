"""Least-privilege tool registry and validation of model-proposed calls."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from secureflow.messages import Finding, Message, Severity


class Tool:
    def __init__(self, name: str, schema: type[BaseModel], handler: Callable[..., Any]) -> None:
        self.name, self.schema, self.handler = name, schema, handler


class ToolRegistry:
    def __init__(self, sandbox: Path, max_calls: int = 20) -> None:
        self.sandbox = sandbox.resolve()
        self.max_calls = max_calls
        self.tools: dict[str, Tool] = {}
        self.allowlists: dict[str, set[str]] = defaultdict(set)
        self.calls = 0

    def register(self, tool: Tool, agents: set[str]) -> None:
        self.tools[tool.name] = tool
        for agent in agents:
            self.allowlists[agent].add(tool.name)

    def validate(self, message: Message) -> list[Finding]:
        findings: list[Finding] = []
        for call in message.tool_calls:
            if call.name not in self.allowlists[message.sender]:
                findings.append(Finding(guard_name="tool_call", category="tool_not_allowed", severity=Severity.HIGH, description="Tool is not allowlisted for sender", evidence=call.name))
                continue
            tool = self.tools.get(call.name)
            if not tool:
                findings.append(Finding(guard_name="tool_call", category="unknown_tool", severity=Severity.HIGH, description="Unknown tool", evidence=call.name))
                continue
            try:
                parsed = tool.schema.model_validate(call.arguments)
                for value in parsed.model_dump().values():
                    if isinstance(value, str) and ("path" in value.lower() or value.startswith(("/", "."))):
                        resolved = (self.sandbox / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
                        if not resolved.is_relative_to(self.sandbox):
                            findings.append(Finding(guard_name="tool_call", category="path_escape", severity=Severity.HIGH, description="Tool path escapes sandbox", evidence="[path]"))
            except ValidationError:
                findings.append(Finding(guard_name="tool_call", category="invalid_arguments", severity=Severity.HIGH, description="Tool arguments failed schema validation", evidence=call.name))
        if self.calls + len(message.tool_calls) > self.max_calls:
            findings.append(Finding(guard_name="tool_call", category="rate_limit", severity=Severity.HIGH, description="Tool call rate limit exceeded", evidence="[rate limit]"))
        return findings


class ToolCallGuard:
    name = "tool_call"

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def check(self, message: Message) -> list[Finding]:
        try:
            return self.registry.validate(message)
        except Exception:
            return [Finding(guard_name=self.name, category="guard_failure", severity=Severity.MEDIUM, description="Tool-call guard failed closed", evidence="[internal error]")]
