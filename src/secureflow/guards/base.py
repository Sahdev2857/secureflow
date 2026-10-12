"""Protocols for guards. Guards return findings instead of raising into a workflow."""

from __future__ import annotations

from typing import Protocol

from secureflow.messages import Finding, GateContext, Message


class Guard(Protocol):
    name: str

    def check(self, message: Message) -> list[Finding]: ...


class ContextGuard(Protocol):
    """Optional stateful guard invoked with the recipient's bounded history."""

    name: str

    def check(self, message: Message, ctx: GateContext) -> list[Finding]: ...
