from src.app import build_agent
from src.config import load_config
from src.fake_llm import FakeLLM
from src.retriever import Hit


class StubRetriever:
    def retrieve(self, question, k=None):
        return [Hit("T1003.001", "LSASS Memory", "T1003.001: LSASS Memory", 0.4, "retrieval:T1003.001#0")]


def test_agent_runs_end_to_end_offline():
    llm = (FakeLLM()
           .on("Material:", "- LSASS memory read by an unusual process")
           .on("Actions:", '{"action": "monitor_lsass_access", "rationale": "credential dumping"}'))
    agent = build_agent(load_config(), llm=llm, retriever=StubRetriever())
    state = agent.run("How do I detect LSASS dumping?")
    assert state.action == "monitor_lsass_access"
    assert [s.name for s in state.steps] == ["retrieve", "lookup", "analyze", "recommend"]
    assert set(state.prompts) == {"summarizer", "recommender"}


def test_format_trace_lists_steps_with_sources():
    from src.app import format_trace

    llm = FakeLLM().on("Actions:", '{"action": "monitor_lsass_access"}')
    state = build_agent(load_config(), llm=llm, retriever=StubRetriever()).run("q " + "x" * 1000)
    text = format_trace(state)
    assert "[1] retrieve  (source: retrieval" in text
    assert "[4] recommend" in text
    assert " ..." in text            # the long question is shortened
