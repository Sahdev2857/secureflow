"""Human review interfaces. Edited content is returned for mandatory re-checking by Workspace."""

from __future__ import annotations

from enum import Enum
from typing import Protocol

from rich.console import Console
from rich.table import Table

from secureflow.messages import Finding, Message


class ApprovalAction(str, Enum):
    APPROVE = "approve"
    EDIT = "edit"
    REJECT = "reject"


class ApprovalResult:
    def __init__(self, action: ApprovalAction, edited_content: str | None = None, reason: str | None = None) -> None:
        self.action, self.edited_content, self.reason = action, edited_content, reason


class Approver(Protocol):
    def review(self, message: Message, findings: list[Finding]) -> ApprovalResult: ...


class AutoApprover:
    def review(self, message: Message, findings: list[Finding]) -> ApprovalResult:
        return ApprovalResult(ApprovalAction.APPROVE)


class AutoRejector:
    def review(self, message: Message, findings: list[Finding]) -> ApprovalResult:
        return ApprovalResult(ApprovalAction.REJECT, reason="automatically rejected")


class ConsoleApprover:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def review(self, message: Message, findings: list[Finding]) -> ApprovalResult:
        self.console.print(f"[bold]Review {message.sender} → {message.recipient}[/bold]\n{message.content}")
        table = Table("Severity", "Category", "Evidence", "Contributors")
        for finding in findings:
            table.add_row(finding.severity.value, finding.category, finding.evidence, ", ".join(finding.contributing_message_ids))
        self.console.print(table)
        choice = input("[a]pprove, [e]dit, [r]eject: ").strip().lower()
        if choice == "e":
            return ApprovalResult(ApprovalAction.EDIT, edited_content=input("Replacement content: "))
        return ApprovalResult(ApprovalAction.APPROVE if choice == "a" else ApprovalAction.REJECT)
