"""The agent under test: a small security assistant built as a plain state machine.

    question -> retrieve (ATT&CK) -> cve_lookup tool -> summarizer sub-agent -> recommend action

Each arrow is a boundary where untrusted text enters the next step. The harness injects at
three of them (seams A, B, C) and measures how often the final action changes.
"""
import dataclasses
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from src.retriever import Hit

DEFAULT_PLAN = ["retrieve", "lookup", "analyze", "recommend"]


@dataclass
class Step:
    """One entry in the trace: what a step saw and produced, and where its input came from."""
    name: str
    input: str
    output: str
    source: str            # provenance of the step's main input, e.g. "retrieval", "tool:cve_lookup"
    seconds: float = 0.0


@dataclass(frozen=True)
class AgentMessage:
    """A message passed between agents. Seam C injects into `content` on its way to the recipient."""
    sender: str            # e.g. "summarizer"
    recipient: str         # e.g. "orchestrator"
    content: str
    provenance: tuple[str, ...] = ()   # sources the sender read to write it, e.g. ("retrieval:T1059#0",)


@dataclass
class AgentState:
    question: str
    cve: str | None = None                                 # CVE ID named in the task, if any
    plan: list[str] = field(default_factory=list)          # step names to run, in order
    hits: list[Hit] = field(default_factory=list)          # retrieved techniques
    tool_results: list[dict] = field(default_factory=list)
    messages: list[AgentMessage] = field(default_factory=list)   # inter-agent messages, in order
    findings: str = ""                                     # content of the summarizer's message
    action: str | None = None                              # final recommended action label
    rationale: str = ""
    steps: list[Step] = field(default_factory=list)        # trace, in execution order
    prompts: dict[str, str] = field(default_factory=dict)  # prompt name -> content hash used

    def record(self, name: str, input: str, output: str, source: str) -> None:
        self.steps.append(Step(name=name, input=input, output=output, source=source))

    def deliver(self, message: AgentMessage) -> None:
        """Hand a message to its recipient. Seam C intercepts exactly here."""
        self.messages.append(message)

    def inbox(self, recipient: str) -> list[AgentMessage]:
        return [m for m in self.messages if m.recipient == recipient]

    def trace(self) -> list[dict]:
        """The trace as plain dicts, ready to write as JSON."""
        return [dataclasses.asdict(s) for s in self.steps]


StepFn = Callable[[AgentState], None]


class Orchestrator:
    """Runs the planned steps in order over one AgentState."""

    def __init__(self, steps: dict[str, StepFn], plan: list[str] | None = None,
                 prompts: dict[str, str] | None = None):
        self.steps = steps
        self.plan = plan or list(DEFAULT_PLAN)
        self.prompts = prompts or {}

    def run(self, question: str, cve: str | None = None) -> AgentState:
        state = AgentState(question=question, cve=cve, plan=list(self.plan), prompts=dict(self.prompts))
        for name in state.plan:
            if name not in self.steps:
                raise KeyError(f"no step registered for {name!r}")
            before = len(state.steps)
            start = time.perf_counter()
            self.steps[name](state)
            if len(state.steps) == before:     # a step that forgot to record still leaves a trace entry
                state.record(name, "", "", "unrecorded")
            state.steps[-1].seconds = time.perf_counter() - start
        return state
