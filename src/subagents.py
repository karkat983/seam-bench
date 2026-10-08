"""Sub-agents: LLM workers the orchestrator delegates to. Their messages are seam C."""
import json
import pathlib

from src.retriever import Hit

PROMPTS = pathlib.Path(__file__).resolve().parent.parent / "prompts"


def load_prompt(name: str) -> str:
    return (PROMPTS / f"{name}.txt").read_text().strip()


def format_context(hits: list[Hit], tool_results: list[dict]) -> str:
    parts = [f"[{h.source}]\n{h.text}" for h in hits]
    parts += [f"[tool:{r['tool']}]\n{json.dumps(r['result'])}" for r in tool_results]
    return "\n\n".join(parts)


class Summarizer:
    """Condenses retrieved techniques and tool output into findings for the orchestrator."""

    def __init__(self, llm, system: str | None = None):
        self.llm = llm
        self.system = system or load_prompt("summarizer")

    def summarize(self, question: str, hits: list[Hit], tool_results: list[dict]) -> str:
        user = f"Question: {question}\n\nMaterial:\n{format_context(hits, tool_results)}"
        return self.llm.complete(self.system, user).text.strip()
