"""LLM abstraction used to keep all tests fully offline."""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel

from secureflow.messages import Message

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    def chat(self, messages: list[Message], response_model: type[T] | None = None) -> tuple[str, list[dict]] | T: ...
