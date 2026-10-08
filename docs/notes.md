# Working notes

## 2026-10-09: local model choice and determinism

**Model.** No API key is used by default; the agent runs on `qwen2.5:7b-instruct` (Q4_K_M,
4.7 GB) through Ollama on an Apple M3 (24 GB). Measured warm throughput: ~4.4 generated tokens/s
and ~145 prompt tokens/s. The 3B variant is ~2.3x faster (10.2 / 304 tokens/s) but is a weaker
agent, so the 7B model is the default here.

**Determinism.** With `temperature: 0` and a fixed `seed`, short constrained answers repeat,
but long free-text answers do not always: three identical calls asking for a 3-sentence
answer (~514 characters) produced **2 distinct outputs out of 3**. Greedy decoding on the GPU
is not bit-exact across calls (floating-point reduction order and prompt-cache reuse can
change the arithmetic slightly, which can flip a near-tie token).

Consequences for the benchmark:

1. Every LLM response is cached by a hash of its full input (commit 035), so scoring and
   re-analysis of a finished run are exactly reproducible.
2. Run-to-run variation is real and is measured rather than assumed away: the stretch phase
   repeats the full matrix over several seeds and reports mean and range.
3. Agent outputs are constrained to a fixed action vocabulary (JSON), which keeps the
   variation that matters (the chosen action) far smaller than free-text variation.
