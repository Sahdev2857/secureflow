"""Run a clean or poisoned source through the SecureFlow gate."""

from __future__ import annotations

import argparse
from pathlib import Path

from secureflow.approval import AutoRejector, ConsoleApprover
from secureflow.audit import AuditLogger
from secureflow.config import SecureFlowConfig
from secureflow.guards.code_command import CodeCommandGuard
from secureflow.guards.injection import InjectionGuard
from secureflow.guards.secrets_pii import SecretsPIIGuard
from secureflow.llm.ollama import OllamaClient
from secureflow.messages import Message, TrustLevel
from secureflow.workspace import Workspace

from agents import PublisherAgent, ResearcherAgent, WriterAgent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", action="store_true")
    parser.add_argument("--auto-reject", action="store_true")
    parser.add_argument("--no-classifier", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).parent
    llm = OllamaClient()
    llm.verify_server()
    researcher, writer, publisher = ResearcherAgent(llm, root / "sources"), WriterAgent(llm), PublisherAgent(root / "published")
    workspace = Workspace([researcher, writer, publisher], [("source", "researcher"), ("researcher", "writer"), ("writer", "publisher")],
                          [InjectionGuard(), SecretsPIIGuard(), CodeCommandGuard()], approver=AutoRejector() if args.auto_reject else ConsoleApprover(),
                          audit=AuditLogger(root / "audit.jsonl"), config=SecureFlowConfig())
    source = "poisoned.txt" if args.attack else "clean_energy.txt"
    raw = (root / "sources" / source).read_text(encoding="utf-8")
    workspace.send(Message(sender="source", recipient="researcher", content=raw, trust=TrustLevel.EXTERNAL))
    notes = researcher.research([source])
    workspace.send(Message(sender="researcher", recipient="writer", content=notes.model_dump_json()))
    draft = writer.write(notes)
    workspace.send(Message(sender="writer", recipient="publisher", content=draft.model_dump_json()))
    print(f"Published {publisher.publish(draft)}")


if __name__ == "__main__":
    main()
