from src.agent import AgentState
from src.retriever import Hit
from src.steps import ToolRegistry, make_lookup, make_retrieve
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
