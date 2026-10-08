from src.agent import AgentState
from src.retriever import Hit
from src.steps import make_retrieve


class StubRetriever:
    def retrieve(self, question, k=None):
        return [Hit(id="T1003.001", name="LSASS Memory", text="T1003.001: LSASS Memory ...", score=0.4,
                    source="retrieval:T1003.001#0")]


def test_retrieve_stores_hits_and_records_step():
    state = AgentState(question="credential dumping from lsass")
    make_retrieve(StubRetriever())(state)
    assert [h.id for h in state.hits] == ["T1003.001"]
    (step,) = state.steps
    assert (step.name, step.input, step.source) == ("retrieve", state.question, "retrieval")
    assert "T1003.001 LSASS Memory" in step.output
