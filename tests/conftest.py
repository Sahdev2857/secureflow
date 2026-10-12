from pathlib import Path

import pytest

from secureflow.guards.classifier import FakeClassifier
from secureflow.llm.fake import FakeLLM


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    path = tmp_path / "sandbox"
    path.mkdir()
    return path


@pytest.fixture
def fake_llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture
def fake_classifier() -> FakeClassifier:
    return FakeClassifier()
