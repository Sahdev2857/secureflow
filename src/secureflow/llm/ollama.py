"""Safe local Ollama client with explicit context/options and structured-output retries."""

from __future__ import annotations

from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from secureflow.config import SecureFlowConfig
from secureflow.messages import Message, ToolCall

T = TypeVar("T", bound=BaseModel)


class OllamaClient:
    def __init__(self, config: SecureFlowConfig | None = None, client: httpx.Client | None = None) -> None:
        self.config = config or SecureFlowConfig()
        self.client = client or httpx.Client(timeout=self.config.request_timeout)

    def verify_server(self) -> None:
        try:
            response = self.client.get(f"{self.config.ollama_url}/api/tags", timeout=self.config.request_timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError("Ollama is unreachable. Start it with `ollama serve`.") from exc
        models = {item.get("name") for item in response.json().get("models", [])}
        if self.config.model not in models:
            raise RuntimeError(f"Ollama model {self.config.model!r} is missing. Run `ollama pull {self.config.model}`.")

    def _payload(self, messages: list[Message], response_model: type[BaseModel] | None = None) -> dict[str, Any]:
        messages = self._bounded_messages(messages)
        payload: dict[str, Any] = {"model": self.config.model, "stream": False, "think": self.config.think,
                                   "messages": [{"role": item.metadata.get("role", "user"), "content": item.content} for item in messages],
                                   "options": {"num_ctx": self.config.num_ctx, "temperature": self.config.temperature}}
        if response_model:
            payload["format"] = response_model.model_json_schema()
        return payload

    def _bounded_messages(self, messages: list[Message]) -> list[Message]:
        """Keep all system instructions; trim oldest untrusted content to the explicit context budget."""
        budget = self.config.num_ctx * 4  # conservative character approximation
        system = [item for item in messages if item.metadata.get("role") == "system"]
        untrusted = [item for item in messages if item.metadata.get("role") != "system"]
        remaining = max(0, budget - sum(len(item.content) for item in system))
        kept: list[Message] = []
        for item in reversed(untrusted):
            if remaining <= 0:
                continue
            content = item.content[-remaining:]
            if len(content) < len(item.content):
                content = "[UNTRUSTED CONTENT TRUNCATED]\n" + content
            kept.append(item.model_copy(update={"content": content}))
            remaining -= len(content)
        # System messages retain their original order and are never truncated.
        return [*system, *reversed(kept)]

    def chat(self, messages: list[Message], response_model: type[T] | None = None) -> tuple[str, list[ToolCall]] | T:
        retry_note = ""
        for attempt in range(3):
            request_messages = messages if not retry_note else [*messages, Message(sender="system", recipient="model", content=retry_note)]
            response = self.client.post(f"{self.config.ollama_url}/api/chat", json=self._payload(request_messages, response_model), timeout=self.config.request_timeout)
            response.raise_for_status()
            body = response.json()
            model_message = body.get("message", {})
            content = model_message.get("content", "")
            # Deliberately discard `thinking` / `thinking`-like fields: they are never logged or forwarded.
            if response_model:
                try:
                    return response_model.model_validate_json(content)
                except ValidationError as exc:
                    if attempt == 2:
                        raise RuntimeError("Ollama returned invalid structured output after 3 attempts") from exc
                    retry_note = f"Your prior JSON failed validation: {exc.errors()[0]['msg']}. Return only schema-valid JSON."
                    continue
            calls = [ToolCall(name=item["function"]["name"], arguments=item["function"].get("arguments", {})) for item in model_message.get("tool_calls", [])]
            return content, calls
        raise AssertionError("unreachable")
