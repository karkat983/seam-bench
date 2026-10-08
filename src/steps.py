"""Step functions for the agent. Each takes the shared AgentState, does one thing, and records it."""
from src.agent import AgentState, StepFn
from src.retriever import Retriever


def make_retrieve(retriever: Retriever) -> StepFn:
    """Seam A lives here: retrieved ATT&CK text is the first untrusted input the agent reads."""

    def retrieve(state: AgentState) -> None:
        state.hits = retriever.retrieve(state.question)
        summary = ", ".join(f"{h.id} {h.name}" for h in state.hits)
        state.record("retrieve", state.question, summary, "retrieval")

    return retrieve
