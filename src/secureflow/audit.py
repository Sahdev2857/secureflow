"""Append-only, redacted JSONL audit records for every attempted transfer."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureflow.messages import Decision, Finding, Message


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe(value: str) -> str:
        value = re.sub(r"(?:AKIA[A-Z0-9]{16}|(?:sk|gh[pousr])-[A-Za-z0-9_-]{12,})", "[redacted]", value)
        return value[:128]

    def record(self, message: Message, findings: list[Finding], decision: Decision, outcome: str, human_action: str | None = None) -> None:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(), "message_id": message.id,
            "sender": message.sender, "recipient": message.recipient, "decision": decision.value,
            "human_action": human_action, "outcome": outcome,
            "assembly_fired": any(f.category == "assembly.emergent" for f in findings),
            "findings": [{"guard_name": f.guard_name, "category": f.category, "severity": f.severity.value,
                          "description": f.description, "evidence": self._safe(f.evidence),
                          "contributing_message_ids": f.contributing_message_ids} for f in findings],
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
