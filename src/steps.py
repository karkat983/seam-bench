"""Step functions for the agent. Each takes the shared AgentState, does one thing, and records it."""
import json

from src.agent import AgentState, StepFn
from src.retriever import Retriever
from src.subagents import Summarizer
from src.tools import find_cve_ids


def make_retrieve(retriever: Retriever) -> StepFn:
    """Seam A lives here: retrieved ATT&CK text is the first untrusted input the agent reads."""

    def retrieve(state: AgentState) -> None:
        state.hits = retriever.retrieve(state.question)
        summary = ", ".join(f"{h.id} {h.name}" for h in state.hits)
        state.record("retrieve", state.question, summary, "retrieval")

    return retrieve


class ToolRegistry:
    """Tools by name, so steps (and later the injectors) can find and wrap them."""

    def __init__(self, *tools):
        self.tools = {t.name: t for t in tools}

    def get(self, name: str):
        if name not in self.tools:
            raise KeyError(f"no tool named {name!r}")
        return self.tools[name]


def make_lookup(registry: ToolRegistry) -> StepFn:
    """Seam B lives here: the tool's output is passed on to the summarizer verbatim."""

    def lookup(state: AgentState) -> None:
        cve = state.cve or next(iter(find_cve_ids(state.question)), None)
        if cve is None:
            state.record("lookup", "", "no CVE mentioned; tool not called", "tool:cve_lookup")
            return
        record = registry.get("cve_lookup").lookup(cve)
        result = {"tool": "cve_lookup", "query": cve, "result": record}
        state.tool_results.append(result)
        state.record("lookup", cve, json.dumps(record), "tool:cve_lookup")

    return lookup


def make_analyze(summarizer: Summarizer) -> StepFn:
    """Delegates to the summarizer sub-agent; its reply becomes the orchestrator's findings."""

    def analyze(state: AgentState) -> None:
        state.findings = summarizer.summarize(state.question, state.hits, state.tool_results)
        sources = [h.source for h in state.hits] + [f"tool:{r['tool']}" for r in state.tool_results]
        state.record("analyze", "; ".join(sources), state.findings, "agent:summarizer")

    return analyze
