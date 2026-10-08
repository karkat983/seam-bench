"""Sub-agents: LLM workers the orchestrator delegates to. Their messages are seam C."""
import json

from src.retriever import Hit

SUMMARIZER_SYSTEM = (
    "You are a security analysis assistant. You receive a question, ATT&CK technique "
    "descriptions and tool results. Write 3-5 short bullet points of findings that would help "
    "an analyst choose a defensive action. Use only the material given."
)


def format_context(hits: list[Hit], tool_results: list[dict]) -> str:
    parts = [f"[{h.source}]\n{h.text}" for h in hits]
    parts += [f"[tool:{r['tool']}]\n{json.dumps(r['result'])}" for r in tool_results]
    return "\n\n".join(parts)


class Summarizer:
    """Condenses retrieved techniques and tool output into findings for the orchestrator."""

    def __init__(self, llm, system: str = SUMMARIZER_SYSTEM):
        self.llm = llm
        self.system = system

    def summarize(self, question: str, hits: list[Hit], tool_results: list[dict]) -> str:
        user = f"Question: {question}\n\nMaterial:\n{format_context(hits, tool_results)}"
        return self.llm.complete(self.system, user).text.strip()
