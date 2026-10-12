"""Workspace transfer gate. No agent receives a message except through `_transfer`."""

from __future__ import annotations

from collections import defaultdict
from uuid import uuid4

from secureflow.agent import Agent
from secureflow.approval import ApprovalAction, Approver, AutoApprover
from secureflow.audit import AuditLogger
from secureflow.config import SecureFlowConfig
from secureflow.guards.base import ContextGuard, Guard
from secureflow.messages import Decision, Finding, GateContext, Message, Severity
from secureflow.policy import Policy, WorkflowHalted


class Workspace:
    def __init__(self, agents: list[Agent], edges: list[tuple[str, str]], guards: list[Guard], policy: Policy | None = None,
                 approver: Approver | None = None, audit: AuditLogger | None = None, config: SecureFlowConfig | None = None,
                 context_guards: list[ContextGuard] | None = None, workflow_id: str | None = None) -> None:
        self.agents = {agent.name: agent for agent in agents}
        self.edges = set(edges)
        self.guards = guards
        self.context_guards = context_guards or []
        self.policy = policy or Policy()
        self.approver = approver or AutoApprover()
        self.audit = audit
        self.config = config or SecureFlowConfig()
        self.workflow_id = workflow_id or str(uuid4())
        self._history: dict[str, list[Message]] = defaultdict(list)

    def send(self, message: Message, to_agent: str | None = None) -> Message:
        """Public entry point; delegates directly to the single guarded transfer method."""
        return self._transfer(message, to_agent or message.recipient)

    def _context(self, recipient: str, pending: Message) -> GateContext:
        recent = [*self._history[recipient], pending][-self.config.assembly_window:]
        chunks: list[str] = []
        budget = self.config.assembly_max_chars
        for item in reversed(recent):
            chunk = f"[{item.id}]\n{item.content}"
            if len(chunk) > budget:
                chunk = chunk[-budget:]
            chunks.append(chunk)
            budget -= len(chunk)
            if budget <= 0:
                break
        assembled = "\n---\n".join(reversed(chunks))
        return GateContext(workflow_id=self.workflow_id, recipient=recipient, recent=recent, assembled_text=assembled)

    def _remember(self, recipient: str, message: Message, rejected: bool = False) -> None:
        stored = message.model_copy(deep=True)
        if rejected:
            stored.metadata["rejected"] = True
        history = self._history[recipient]
        history.append(stored)
        while len(history) > self.config.assembly_window or sum(len(item.content) for item in history) > self.config.assembly_max_chars:
            history.pop(0)

    def _findings(self, message: Message, recipient: str) -> list[Finding]:
        findings: list[Finding] = []
        for guard in self.guards:
            try:
                findings.extend(guard.check(message))
            except Exception:
                findings.append(Finding(guard_name=getattr(guard, "name", "unknown"), category="guard_failure", severity=Severity.MEDIUM,
                                        description="Guard failed closed", evidence="[internal error]"))
        ctx = self._context(recipient, message)
        if self.config.assembly_enabled and len(ctx.recent) >= 2:
            for guard in self.context_guards:
                try:
                    findings.extend(guard.check(message, ctx))
                except Exception:
                    findings.append(Finding(guard_name=getattr(guard, "name", "context"), category="guard_failure", severity=Severity.MEDIUM,
                                            description="Context guard failed closed", evidence="[internal error]"))
        return findings

    def _record(self, message: Message, findings: list[Finding], decision: Decision, outcome: str, action: str | None = None) -> None:
        if self.audit:
            self.audit.record(message, findings, decision, outcome, action)

    def _transfer(self, message: Message, to_agent: str) -> Message:
        if to_agent not in self.agents:
            raise KeyError(f"Unknown recipient agent: {to_agent}")
        if self.edges and (message.sender, to_agent) not in self.edges:
            raise WorkflowHalted("Undeclared workspace edge", [Finding(guard_name="workspace", category="edge", severity=Severity.HIGH, description="Undeclared agent edge", evidence="[edge]")])
        current = message.model_copy(update={"recipient": to_agent})
        while True:
            findings = self._findings(current, to_agent)
            decision = self.policy.decide(findings)
            if decision is Decision.BLOCK:
                self._remember(to_agent, current, rejected=True)
                self._record(current, findings, decision, "blocked")
                raise WorkflowHalted("Transfer blocked by policy", findings)
            if decision is Decision.FLAG:
                result = self.approver.review(current, findings)
                if result.action is ApprovalAction.REJECT:
                    self._remember(to_agent, current, rejected=True)
                    self._record(current, findings, decision, "rejected", result.action.value)
                    raise WorkflowHalted("Transfer rejected by approver", findings)
                if result.action is ApprovalAction.EDIT:
                    if result.edited_content is None:
                        raise ValueError("An edit approval requires replacement content")
                    current = current.model_copy(update={"content": result.edited_content})
                    continue
                self._record(current, findings, decision, "approved", result.action.value)
            else:
                self._record(current, findings, decision, "delivered")
            self._remember(to_agent, current)
            self.agents[to_agent].receive(current)
            return current
