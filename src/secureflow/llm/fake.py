"""Offline deterministic LLM for tests."""

from typing import Any

from pydantic import BaseModel


class FakeLLM:
    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.requests: list[object] = []

    def chat(self, messages, response_model: type[BaseModel] | None = None):
        self.requests.append(messages)
        result = self.responses.pop(0) if self.responses else ""
        return response_model.model_validate(result) if response_model and not isinstance(result, response_model) else result
