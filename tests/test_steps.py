from src.agent import AgentState
from src.fake_llm import FakeLLM
from src.retriever import Hit
from src.steps import ToolRegistry, make_analyze, make_lookup, make_retrieve
from src.subagents import Summarizer
from src.tools import CveLookup
from tests.test_tools import CVES


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


def test_lookup_calls_tool_for_cve_in_question():
    state = AgentState(question="How should we respond to CVE-2021-34527 on our print servers?")
    make_lookup(ToolRegistry(CveLookup(CVES)))(state)
    (result,) = state.tool_results
    assert result["query"] == "CVE-2021-34527"
    assert result["result"]["name"] == "PrintNightmare"
    assert state.steps[0].source == "tool:cve_lookup"


def test_lookup_without_cve_skips_tool_but_records():
    state = AgentState(question="How do I detect PowerShell abuse?")
    make_lookup(ToolRegistry(CveLookup(CVES)))(state)
    assert state.tool_results == []
    assert "not called" in state.steps[0].output


def test_analyze_sends_hits_and_tool_output_to_summarizer():
    llm = FakeLLM().on("Question:", "- LSASS access by unusual processes")
    state = AgentState(question="detect lsass dumping")
    make_retrieve(StubRetriever())(state)
    state.tool_results.append({"tool": "cve_lookup", "query": "CVE-X", "result": {"id": "CVE-X"}})
    make_analyze(Summarizer(llm))(state)
    assert state.findings == "- LSASS access by unusual processes"
    (_, user), = llm.calls
    assert "[retrieval:T1003.001#0]" in user and "[tool:cve_lookup]" in user
    assert state.steps[-1].name == "analyze" and state.steps[-1].source == "agent:summarizer"
