import pytest

from src.agent import DEFAULT_PLAN, Orchestrator


def test_runs_steps_in_plan_order():
    seen = []
    steps = {name: (lambda st, n=name: seen.append(n)) for name in DEFAULT_PLAN}
    Orchestrator(steps).run("q")
    assert seen == ["retrieve", "lookup", "analyze", "recommend"]


def test_custom_plan_and_state_passed_through():
    def recommend(state):
        state.action = f"answer for {state.question} / {state.cve}"

    state = Orchestrator({"recommend": recommend}, plan=["recommend"]).run("q1", cve="CVE-2021-44228")
    assert state.action == "answer for q1 / CVE-2021-44228"
    assert state.plan == ["recommend"]


def test_unknown_step_fails_loudly():
    with pytest.raises(KeyError, match="analyze"):
        Orchestrator({"retrieve": lambda s: None}, plan=["retrieve", "analyze"]).run("q")


def test_every_step_leaves_a_timed_trace_entry():
    def retrieve(state):
        state.record("retrieve", state.question, "T1059", "retrieval")

    steps = {"retrieve": retrieve, "analyze": lambda s: None}
    state = Orchestrator(steps, plan=["retrieve", "analyze"]).run("q")
    trace = state.trace()
    assert [t["name"] for t in trace] == ["retrieve", "analyze"]
    assert trace[0] == {"name": "retrieve", "input": "q", "output": "T1059", "source": "retrieval",
                        "seconds": trace[0]["seconds"]}
    assert trace[1]["source"] == "unrecorded"
    assert all(t["seconds"] >= 0 for t in trace)
