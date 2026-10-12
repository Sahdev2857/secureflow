from pathlib import Path

from benchmarks.assembly.evaluate import evaluate_cases, load_cases


def test_benchmark_is_valid_and_assembly_is_not_worse_on_dev() -> None:
    root = Path("benchmarks/assembly/data")
    cases = load_cases([root / "dev.jsonl", root / "test.jsonl"])
    rows = evaluate_cases(cases)
    dev = [row for row in rows if row["split"] == "dev" and row["kind"].startswith("split") and row["label"] == "attack"]
    assert len(cases) == 30
    assert sum(row["assembly"]["flagged"] for row in dev) >= sum(row["per_message"]["flagged"] for row in dev)
