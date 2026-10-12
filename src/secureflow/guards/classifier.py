"""Optional prompt-injection classifier with an offline deterministic substitute."""

from __future__ import annotations

import logging
from typing import Protocol


LOG = logging.getLogger(__name__)


class Classifier(Protocol):
    def score(self, text: str) -> float: ...


class FakeClassifier:
    """Deterministic test classifier; it never downloads a model."""

    def __init__(self, scores: dict[str, float] | None = None, default: float = 0.0) -> None:
        self.scores = scores or {}
        self.default = default

    def score(self, text: str) -> float:
        return max((score for needle, score in self.scores.items() if needle in text), default=self.default)


class HFClassifier:
    """Lazy Hugging Face classifier. Optional dependencies are not required to import SecureFlow."""

    model_id = "protectai/deberta-v3-base-prompt-injection-v2"

    def __init__(self, model_id: str | None = None) -> None:
        self.model_id = model_id or self.model_id
        self._pipeline = None

    def _load(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline
        except ImportError as exc:
            LOG.warning("Prompt-injection classifier unavailable; using rule-based guards only")
            raise RuntimeError("Install secureflow[classifier] to enable HFClassifier") from exc
        self._pipeline = pipeline("text-classification", model=self.model_id, truncation=True)

    def score(self, text: str) -> float:
        self._load()
        result = self._pipeline(text)[0]
        # The published model labels its injection class positively; use score only for that class.
        return float(result["score"]) if "inject" in str(result["label"]).lower() else 1.0 - float(result["score"])
