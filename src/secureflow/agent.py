"""Minimal agent interface; workspace delivery is intentionally separate from generation."""

from __future__ import annotations

from typing import Protocol

from secureflow.messages import Message


class Agent(Protocol):
    name: str

    def receive(self, message: Message) -> None: ...


class InboxAgent:
    """Simple agent useful for tests and deterministic orchestration."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.inbox: list[Message] = []

    def receive(self, message: Message) -> None:
        self.inbox.append(message)
