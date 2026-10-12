import httpx

from pydantic import BaseModel

from secureflow.llm.ollama import OllamaClient
from secureflow.messages import Message


class Answer(BaseModel):
    value: str


def test_options_thinking_and_structured_retry() -> None:
    calls = []
    replies = iter([{"message": {"content": "not json", "thinking": "secret"}}, {"message": {"content": '{"value":"ok"}', "thinking": "secret"}}])
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=next(replies))
    client = OllamaClient(client=httpx.Client(transport=httpx.MockTransport(handler)))
    answer = client.chat([Message(sender="a", recipient="b", content="hi")], Answer)
    assert answer.value == "ok"
    payload = calls[0].json() if hasattr(calls[0], "json") else None
    import json
    sent = json.loads(calls[0].content)
    assert sent["options"]["num_ctx"] == 8192 and sent["think"] is False


def test_context_truncation_preserves_system_message() -> None:
    from secureflow.config import SecureFlowConfig
    client = OllamaClient(config=SecureFlowConfig(num_ctx=2), client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    system = Message(sender="system", recipient="model", content="SYSTEM INSTRUCTIONS", metadata={"role": "system"})
    untrusted = Message(sender="a", recipient="model", content="x" * 100)
    payload = client._payload([system, untrusted])
    assert payload["messages"][0]["content"] == "SYSTEM INSTRUCTIONS"
    assert len(payload["messages"]) == 1  # untrusted content is dropped first when no space remains
