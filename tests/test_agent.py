"""Smoke tests for the full agent on real tasks. Offline ones use a scripted LLM."""
from src.app import build_agent
from src.config import load_config
from src.fake_llm import FakeLLM
from src.tasks import load_validated
from tests.test_app import StubRetriever


def test_clean_task_returns_expected_action_offline():
    cfg = load_config()
    task = next(t for t in load_validated(cfg) if t.id == "t04")      # Log4Shell, uses the CVE tool
    llm = (FakeLLM()
           .on("Material:", "- CVE-2021-44228 (Log4Shell) is remote code execution on public servers")
           .on("Actions:", '{"action": "patch_public_facing_service", "rationale": "exposed RCE"}'))
    state = build_agent(cfg, llm=llm, retriever=StubRetriever()).run(task.question, cve=task.cve)
    assert state.action == task.expected_action
    # the tool ran on the task's CVE and its output reached the summarizer
    assert state.tool_results[0]["result"]["name"] == "Log4Shell"
    summarizer_input = next(user for system, user in llm.calls if "Material:" in user)
    assert "Log4Shell" in summarizer_input
