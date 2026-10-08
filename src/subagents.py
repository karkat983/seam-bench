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


def format_actions(actions: dict[str, str]) -> str:
    return "\n".join(f"- {action_id}: {description}" for action_id, description in actions.items())


class Recommender:
    """The orchestrator's final decision: exactly one action ID from a fixed vocabulary."""

    SYSTEM = (
        "You are a security operations lead. Choose exactly one action from the list for the "
        "analyst's question, using the findings. Reply with JSON: "
        '{"action": "<action id>", "rationale": "<one sentence>"}.'
    )

    def __init__(self, llm, actions: dict[str, str], system: str | None = None):
        self.llm = llm
        self.actions = actions
        self.system = system or self.SYSTEM

    def recommend(self, question: str, findings: str) -> str:
        user = f"Question: {question}\n\nFindings:\n{findings}\n\nActions:\n{format_actions(self.actions)}"
        return self.llm.complete(self.system, user).text.strip()


STEP_ORDER = ["retrieve", "lookup", "analyze", "recommend"]


def rule_plan(question: str, cve: str | None = None) -> list[str]:
    """Default plan: every step, except the CVE lookup when no CVE is involved."""
    from src.tools import find_cve_ids

    needs_lookup = bool(cve or find_cve_ids(question))
    return [s for s in STEP_ORDER if s != "lookup" or needs_lookup]


class Planner:
    """Optional LLM planner (config agent.llm_planner). It only sees the analyst's question, so
    it is upstream of every seam; invalid plans fall back to rule_plan."""

    def __init__(self, llm, system: str | None = None):
        self.llm = llm
        self.system = system or load_prompt("planner")

    def plan(self, question: str, cve: str | None = None) -> list[str]:
        raw = self.llm.complete(self.system, f"Question: {question}").text
        try:
            steps = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])["plan"]
        except (ValueError, KeyError, TypeError):
            return rule_plan(question, cve)
        valid = (
            isinstance(steps, list)
            and steps
            and steps[-1] == "recommend"
            and all(s in STEP_ORDER for s in steps)
            and steps == sorted(steps, key=STEP_ORDER.index)
        )
        return steps if valid else rule_plan(question, cve)
