# ADR 001: a plain Python state machine instead of LangGraph

**Status:** accepted (2026-10-09)

## Context

The agent exists to be measured, not shipped. Every injection experiment needs to know exactly
which step read which text, in which order, and what it produced, so that an attack's effect
can be traced from the seam where it entered to the final action.

## Options

1. **LangGraph.** Graph-based agent framework with checkpointing and conditional edges.
   Familiar from previous work and convenient for open-ended tool loops.
2. **Plain Python.** A fixed sequence of step functions over one `AgentState` dataclass, each
   appending to an explicit trace.

## Decision

Plain Python.

- The control flow is fixed (retrieve -> tool -> summarize -> recommend), so a graph engine
  adds no capability, only indirection between the code and the trace.
- Every step and seam is a visible function call, which makes the injection points easy to
  read, test and explain.
- No framework version drift: results stay reproducible without pinning a fast-moving library.
- Offline tests run with a scripted fake LLM in milliseconds.

## Consequences

- No built-in checkpointing or retries; the cache (`src/cache.py`) and a simple retry wrapper
  cover what the benchmark needs.
- The per-seam view (where the attack entered) is a first-class part of the trace, which is
  the property seam-bench is built around.
- If a later experiment needs model-chosen tool loops, the step functions can be wrapped as
  LangGraph nodes without changing the injectors or the metrics.
