# Assembly benchmark

Run `PYTHONPATH=src:. python -m benchmarks.assembly.evaluate`. The data is small, synthetic, and uses only fake secrets, `example.invalid`, and harmless `/tmp` paths. Tune only against `data/dev.jsonl`; `data/test.jsonl` is held out.

This measures rule-based detection on this dataset only. It cannot establish resistance to semantic paraphrase or determined attackers. Reports are generated in `results/`.
