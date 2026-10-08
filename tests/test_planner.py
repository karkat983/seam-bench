from src.fake_llm import FakeLLM
from src.subagents import Planner, rule_plan


def test_rule_plan_skips_lookup_without_a_cve():
    assert rule_plan("How do I detect PowerShell abuse?") == ["retrieve", "analyze", "recommend"]
    assert rule_plan("Respond to CVE-2021-44228") == ["retrieve", "lookup", "analyze", "recommend"]
    assert rule_plan("anything", cve="CVE-2017-0144")[1] == "lookup"


def test_llm_plan_is_used_when_valid():
    llm = FakeLLM(default='{"plan": ["retrieve", "recommend"]}')
    assert Planner(llm).plan("q") == ["retrieve", "recommend"]


def test_invalid_llm_plans_fall_back_to_rules():
    for reply in ["not json", '{"plan": ["recommend", "retrieve"]}', '{"plan": ["retrieve", "hack"]}',
                  '{"plan": ["retrieve"]}', '{"steps": []}']:
        assert Planner(FakeLLM(default=reply)).plan("q") == ["retrieve", "analyze", "recommend"], reply
