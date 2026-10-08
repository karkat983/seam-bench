"""The agent under test: a small security assistant built as a plain state machine.

    question -> retrieve (ATT&CK) -> cve_lookup tool -> summarizer sub-agent -> recommend action

Each arrow is a boundary where untrusted text enters the next step. The harness injects at
three of them (seams A, B, C) and measures how often the final action changes.
"""
from dataclasses import dataclass, field

from src.retriever import Hit


@dataclass
class Step:
    """One entry in the trace: what a step saw and produced, and where its input came from."""
    name: str
    input: str
    output: str
    source: str            # provenance of the step's main input, e.g. "retrieval", "tool:cve_lookup"


@dataclass
class AgentState:
    question: str
    cve: str | None = None                                 # CVE ID named in the task, if any
    plan: list[str] = field(default_factory=list)          # step names to run, in order
    hits: list[Hit] = field(default_factory=list)          # retrieved techniques
    tool_results: list[dict] = field(default_factory=list)
    findings: str = ""                                     # summarizer sub-agent's message
    action: str | None = None                              # final recommended action label
    rationale: str = ""
    steps: list[Step] = field(default_factory=list)        # trace, in execution order

    def record(self, name: str, input: str, output: str, source: str) -> None:
        self.steps.append(Step(name=name, input=input, output=output, source=source))
