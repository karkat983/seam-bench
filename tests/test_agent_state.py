from src.agent import AgentState


def test_new_state_is_empty_and_records_steps_in_order():
    state = AgentState(question="How do I detect T1059?")
    assert state.action is None and state.steps == [] and state.hits == []
    state.record("retrieve", "q", "3 hits", "retrieval")
    state.record("recommend", "findings", '{"action": "x"}', "agent:summarizer")
    assert [s.name for s in state.steps] == ["retrieve", "recommend"]
    assert state.steps[1].source == "agent:summarizer"


def test_states_do_not_share_lists():
    a, b = AgentState(question="a"), AgentState(question="b")
    a.plan.append("retrieve")
    assert b.plan == []
