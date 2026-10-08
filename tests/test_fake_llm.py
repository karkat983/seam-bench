from src.fake_llm import FakeLLM
from src.llm import make_client


def test_first_matching_rule_wins_and_calls_are_recorded():
    llm = FakeLLM().on("summarize", "SUMMARY").on("recommend", '{"action": "monitor"}')
    assert llm.complete("You summarize text.", "x").text == "SUMMARY"
    assert llm.complete("sys", "please recommend").text == '{"action": "monitor"}'
    assert llm.complete("sys", "other").text == "{}"
    assert len(llm.calls) == 3


def test_fake_provider_from_config():
    assert isinstance(make_client({"provider": "fake", "model": "x"}), FakeLLM)
