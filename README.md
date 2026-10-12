# SecureFlow

SecureFlow is a lightweight Python framework for multi-agent workflows whose hand-offs are security-gated. Agent output, tool results, external sources, and user input are untrusted by default.

## Install and run

```bash
pip install -e '.[dev]'
python examples/research_write_publish/run_demo.py
python examples/research_write_publish/run_demo.py --attack --auto-reject
PYTHONPATH=src:. python -m benchmarks.assembly.evaluate
```

The demo requires a local Ollama server and `gemma4:e4b`: start it with `ollama serve` and install the model with `ollama pull gemma4:e4b`. Scenario B pauses for review before the poisoned source enters the researcher; `--auto-reject` demonstrates halting in CI. Audit records are JSONL and redact secret evidence.

## Extend

Implement `Guard.check(message) -> list[Finding]` for a stateless guard, or `ContextGuard.check(message, ctx)` for assembly-aware checks, then pass it to `Workspace`. Implement an agent with `name` and `receive`; send every hand-off through `Workspace.send`. Tool calls use per-agent allowlists and Pydantic argument schemas.

## Split-payload threat model

An attacker can divide a payload across several messages, making each fragment look harmless. `AssemblyGuard` retains a bounded recipient history, examines normalized/decoded assembled views, and reports only signals that emerge from the combination. Run the generated benchmark report with the command above; never tune rules against its held-out test data.

## Limitations

This is defense in depth, not a guarantee. Pattern and classifier checks can miss paraphrases, encoded formats, and novel attacks; human approval can make mistakes. The benchmark is small and synthetic, so its results do not generalize beyond that data. SecureFlow never executes model output, but integrations must preserve that property.
