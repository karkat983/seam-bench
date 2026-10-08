import pytest

from src.llm import LLMResponse
from src.usage import MeteredClient


class Stub:
    model = "claude-opus-5-5"

    def complete(self, system, user):
        return LLMResponse(text="ok", model=self.model, input_tokens=1000, output_tokens=200)


def test_counts_calls_and_tokens():
    meter = MeteredClient(Stub())
    meter.complete("s", "u")
    meter.complete("s", "u2")
    usage = meter.by_model["claude-opus-5-5"]
    assert (usage.calls, usage.input_tokens, usage.output_tokens) == (2, 2000, 400)


def test_cost_uses_price_table():
    meter = MeteredClient(Stub())
    meter.complete("s", "u")
    # 1000 * $4/M + 200 * $20/M = 0.004 + 0.004
    assert meter.total_cost_usd() == pytest.approx(0.008)


def test_unknown_model_costs_nothing():
    stub = Stub()
    stub.model = "qwen2.5:7b-instruct"
    meter = MeteredClient(stub)
    meter.complete("s", "u")
    assert meter.total_cost_usd() == 0
    assert "qwen2.5:7b-instruct" in meter.report()
