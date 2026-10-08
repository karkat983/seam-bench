"""Count real LLM calls, tokens and estimated cost.

Wrap the raw client *inside* the cache (CachedClient(MeteredClient(raw))) so only calls that
actually reach a model are counted.
"""
import time
from collections import defaultdict
from dataclasses import dataclass, field

# USD per million tokens (input, output). Local models cost nothing per token.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}


@dataclass
class ModelUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0

    def cost_usd(self, model: str) -> float:
        price_in, price_out = PRICES.get(model, (0.0, 0.0))
        return (self.input_tokens * price_in + self.output_tokens * price_out) / 1e6


@dataclass
class MeteredClient:
    client: object
    by_model: dict[str, ModelUsage] = field(default_factory=lambda: defaultdict(ModelUsage))

    @property
    def model(self):
        return getattr(self.client, "model", None)

    def options(self):
        return self.client.options() if hasattr(self.client, "options") else {}

    def complete(self, system: str, user: str):
        start = time.perf_counter()
        response = self.client.complete(system, user)
        usage = self.by_model[response.model]
        usage.calls += 1
        usage.input_tokens += response.input_tokens
        usage.output_tokens += response.output_tokens
        usage.seconds += time.perf_counter() - start
        return response

    def total_cost_usd(self) -> float:
        return sum(u.cost_usd(m) for m, u in self.by_model.items())

    def report(self) -> str:
        lines = [f"{'model':<24} {'calls':>6} {'in tok':>9} {'out tok':>8} {'secs':>8} {'USD':>8}"]
        for model, u in sorted(self.by_model.items()):
            lines.append(
                f"{model:<24} {u.calls:>6} {u.input_tokens:>9} {u.output_tokens:>8} "
                f"{u.seconds:>8.1f} {u.cost_usd(model):>8.4f}"
            )
        return "\n".join(lines)
