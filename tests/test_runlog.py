from src.config import load_config
from src.fake_llm import FakeLLM
from src.runlog import append_run, read_runs
from tests.test_app import StubRetriever


def test_runs_append_as_jsonl_with_full_trace(tmp_path):
    from src.app import build_agent

    llm = FakeLLM().on("Actions:", '{"action": "monitor_lsass_access", "rationale": "r"}')
    agent = build_agent(load_config(), llm=llm, retriever=StubRetriever())
    path = tmp_path / "runs" / "test.jsonl"
    for q in ("q1", "q2"):
        append_run(path, agent.run(q), task="t", seam="none")
    runs = read_runs(path)
    assert [r["question"] for r in runs] == ["q1", "q2"]
    assert runs[0]["action"] == "monitor_lsass_access"
    assert runs[0]["seam"] == "none"
    assert [s["name"] for s in runs[0]["trace"]] == ["retrieve", "lookup", "analyze", "recommend"]
    assert runs[0]["messages"][0]["sender"] == "summarizer"
