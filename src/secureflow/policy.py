"""Conservative policy mapping guard severity to transfer decisions."""

from __future__ import annotations

from dataclasses import dataclass

from secureflow.messages import Decision, Finding, Severity


class WorkflowHalted(RuntimeError):
    def __init__(self, message: str, findings: list[Finding]) -> None:
        super().__init__(message)
        self.findings = findings


@dataclass(frozen=True, slots=True)
class Policy:
    block_on_critical: bool = False

    def decide(self, findings: list[Finding]) -> Decision:
        if self.block_on_critical and any(f.severity is Severity.CRITICAL for f in findings):
            return Decision.BLOCK
        if any(f.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} for f in findings):
            return Decision.FLAG
        return Decision.ALLOW
