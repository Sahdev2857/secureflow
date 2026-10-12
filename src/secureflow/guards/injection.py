"""Detect direct prompt-injection instructions before they reach another agent."""

from __future__ import annotations

import base64
import re

from secureflow.guards.classifier import Classifier
from secureflow.messages import Finding, Message, Severity


class InjectionGuard:
    name = "injection"
    _patterns = (
        r"ignore (?:all |any |the )?(?:previous|prior|above) instructions?",
        r"you are now (?:a|an|the)?\s*\w+",
        r"(?:reveal|show|print|extract).{0,40}(?:system prompt|developer message|hidden instructions)",
        r"(?:act as|roleplay as|pretend to be).{0,40}(?:without|bypass|jailbreak)",
        r"(?:the next agent|the assistant)\s*[:,]",
    )
    _compiled = tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in _patterns)
    _b64 = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")

    def __init__(self, classifier: Classifier | None = None, threshold: float = 0.75) -> None:
        self.classifier = classifier
        self.threshold = threshold

    def _finding(self, category: str, severity: Severity, text: str, start: int = 0) -> Finding:
        return Finding(guard_name=self.name, category=category, severity=severity,
                       description="Potential prompt-injection content", evidence=text[:32] + "…", span=(start, start + len(text)))

    def check(self, message: Message) -> list[Finding]:
        try:
            content = message.content
            findings: list[Finding] = []
            for pattern in self._compiled:
                if match := pattern.search(content):
                    findings.append(self._finding("prompt_injection", Severity.HIGH, match.group(), match.start()))
            if re.search(r"[\u200b-\u200f\u2060\ufeff]", content):
                findings.append(self._finding("hidden_unicode", Severity.MEDIUM, "[zero-width character]"))
            if "<!--" in content or "-->" in content:
                findings.append(self._finding("hidden_markup", Severity.MEDIUM, "[HTML comment]"))
            for match in self._b64.finditer(content):
                try:
                    decoded = base64.b64decode(match.group(), validate=True).decode("utf-8", errors="ignore")
                except (ValueError, UnicodeDecodeError):
                    continue
                if any(pattern.search(decoded) for pattern in self._compiled):
                    findings.append(self._finding("encoded_injection", Severity.HIGH, "[base64 instruction]", match.start()))
            if self.classifier:
                score = max((self.classifier.score(content[i:i + 2048]) for i in range(0, max(1, len(content)), 1536)), default=0.0)
                if score >= self.threshold:
                    findings.append(Finding(guard_name=self.name, category="classifier_injection", severity=Severity.MEDIUM,
                                            description=f"Classifier injection score {score:.2f}", evidence="[classifier signal]"))
            return findings
        except Exception:
            return [Finding(guard_name=self.name, category="guard_failure", severity=Severity.MEDIUM,
                            description="Injection guard failed closed", evidence="[internal error]")]
