"""A scripted stand-in for an LLM, so agent logic can be tested offline and instantly.

Rules are checked in order; the first whose `when` substring occurs in the system prompt or
user message decides the reply. Every call is recorded for assertions.
"""
from dataclasses import dataclass, field

from src.llm import LLMResponse


@dataclass
class FakeLLM:
    rules: list[tuple[str, str]] = field(default_factory=list)   # (when, reply)
    default: str = "{}"
    model: str = "fake-llm"
    calls: list[tuple[str, str]] = field(default_factory=list)

    def on(self, when: str, reply: str) -> "FakeLLM":
        self.rules.append((when, reply))
        return self

    def options(self) -> dict:
        return {}

    def complete(self, system: str, user: str) -> LLMResponse:
        self.calls.append((system, user))
        reply = next((r for when, r in self.rules if when in system or when in user), self.default)
        # ~4 characters per token, so usage reports look plausible in tests
        tokens_in, tokens_out = len(system + user) // 4, len(reply) // 4
        return LLMResponse(text=reply, model=self.model, input_tokens=tokens_in, output_tokens=tokens_out)
