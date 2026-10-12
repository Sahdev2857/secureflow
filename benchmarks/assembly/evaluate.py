"""Offline, deterministic comparison of per-message and assembly-aware gates."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from benchmarks.assembly.schema import Case
from secureflow.agent import InboxAgent
from secureflow.approval import AutoRejector
from secureflow.config import SecureFlowConfig
from secureflow.guards.assembly import AssemblyGuard
from secureflow.guards.code_command import CodeCommandGuard
from secureflow.guards.injection import InjectionGuard
from secureflow.guards.secrets_pii import SecretsPIIGuard
from secureflow.messages import Message
from secureflow.policy import WorkflowHalted
from secureflow.workspace import Workspace

ROOT = Path(__file__).parent


def load_cases(paths: list[Path]) -> list[Case]:
    return [Case.model_validate_json(line) for path in paths for line in path.read_text().splitlines() if line.strip()]


def run_case(case: Case, assembly: bool) -> dict[str, Any]:
    recipient = case.fragments[0].recipient
    guards = [InjectionGuard(), SecretsPIIGuard(), CodeCommandGuard()]
    workspace = Workspace([InboxAgent(recipient)], [], guards, approver=AutoRejector(),
                          config=SecureFlowConfig(assembly_enabled=assembly),
                          context_guards=[AssemblyGuard()] if assembly else [])
    first = None
    for index, fragment in enumerate(case.fragments, 1):
        try:
            workspace.send(Message(sender=fragment.sender, recipient=recipient, content=fragment.content, trust=fragment.trust))
        except WorkflowHalted:
            if first is None:
                first = index
    return {"flagged": first is not None, "first_fragment": first}


def metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    attack = [row for row in rows if row["label"] == "attack"]
    benign = [row for row in rows if row["label"] == "benign"]
    tp = sum(row["assembly"]["flagged"] for row in attack)
    fp = sum(row["assembly"]["flagged"] for row in benign)
    return {"detection_rate": tp / len(attack) if attack else 0.0, "false_positive_rate": fp / len(benign) if benign else 0.0,
            "precision": tp / (tp + fp) if tp + fp else 0.0}


def evaluate_cases(cases: list[Case]) -> list[dict[str, Any]]:
    return [{"id": case.id, "split": case.split, "label": case.label, "kind": case.kind,
             "per_message": run_case(case, False), "assembly": run_case(case, True)} for case in cases]


def report(rows: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    sections = {split: [row for row in rows if row["split"] == split] for split in ("dev", "test")}
    payload = {split: {"metrics": metrics(part), "cases": part} for split, part in sections.items()}
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(payload, indent=2) + "\n")
    markdown = ["# Assembly benchmark report", "", "| Split | Detection | False positive | Precision |", "|---|---:|---:|---:|"]
    for split, data in payload.items():
        m = data["metrics"]
        markdown.append(f"| {split} | {m['detection_rate']:.0%} | {m['false_positive_rate']:.0%} | {m['precision']:.0%} |")
    (output / "report.md").write_text("\n".join(markdown) + "\n")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--classifier", choices=["fake", "hf"], default="fake")
    parser.add_argument("--with-llm", action="store_true")
    args = parser.parse_args()
    if args.with_llm:
        print("--with-llm is not included in the offline benchmark; run the example separately.")
    data = load_cases([ROOT / "data/dev.jsonl", ROOT / "data/test.jsonl"])
    payload = report(evaluate_cases(data), ROOT / "results")
    table = Table("Split", "Detection", "False positive", "Precision")
    for split, section in payload.items():
        m = section["metrics"]
        table.add_row(split, f"{m['detection_rate']:.0%}", f"{m['false_positive_rate']:.0%}", f"{m['precision']:.0%}")
    Console().print(table)


if __name__ == "__main__":
    main()
