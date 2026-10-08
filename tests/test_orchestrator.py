import pytest

from src.agent import DEFAULT_PLAN, Orchestrator


def test_runs_steps_in_plan_order():
    seen = []
    steps = {name: (lambda st, n=name: seen.append(n)) for name in DEFAULT_PLAN}
    Orchestrator(steps).run("q")
    assert seen == ["retrieve", "analyze", "recommend"]


def test_custom_plan_and_state_passed_through():
    def recommend(state):
        state.action = f"answer for {state.question} / {state.cve}"

    state = Orchestrator({"recommend": recommend}, plan=["recommend"]).run("q1", cve="CVE-2021-44228")
    assert state.action == "answer for q1 / CVE-2021-44228"
    assert state.plan == ["recommend"]


def test_unknown_step_fails_loudly():
    with pytest.raises(KeyError, match="analyze"):
        Orchestrator({"retrieve": lambda s: None}, plan=["retrieve", "analyze"]).run("q")
