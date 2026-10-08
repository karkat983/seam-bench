"""One small interface over the LLM providers the benchmark can run on.

Every agent step calls `client.complete(system, user)` and gets back an `LLMResponse`.
The provider and model come from config.yaml, so a reader can swap them without code changes.
"""
import json
import os
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str            # model that actually produced the text
    input_tokens: int
    output_tokens: int
    refused: bool = False  # provider-side safety decline (Anthropic stop_reason "refusal")


class OllamaClient:
    """Local models via Ollama's /api/chat endpoint (https://github.com/ollama/ollama)."""

    def __init__(self, model: str, host: str = "http://localhost:11434", max_tokens: int = 512):
        self.model = model
        self.host = os.environ.get("OLLAMA_HOST", host).rstrip("/")
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str) -> LLMResponse:
        body = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"num_predict": self.max_tokens},
        }
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.load(resp)
        return LLMResponse(
            text=data["message"]["content"],
            model=data.get("model", self.model),
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
        )


class AnthropicClient:
    """Claude via the official Anthropic SDK (only imported when this provider is selected).

    Server-side refusal fallbacks are on: if the requested model declines, the API re-runs the
    request on a fallback model in the same call. `LLMResponse.model` records which model
    actually answered, so results can be split by serving model.
    """

    def __init__(self, model: str = "claude-opus-5-5", max_tokens: int = 512, effort: str = "medium"):
        import anthropic

        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self._client = anthropic.Anthropic()

    def complete(self, system: str, user: str) -> LLMResponse:
        response = self._client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        return LLMResponse(
            text=text,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            refused=response.stop_reason == "refusal",
        )


def make_client(llm_cfg: dict):
    provider = llm_cfg["provider"]
    max_tokens = llm_cfg.get("max_tokens", 512)
    if provider == "ollama":
        host = llm_cfg.get("ollama_host", "http://localhost:11434")
        return OllamaClient(llm_cfg["model"], host, max_tokens)
    if provider == "anthropic":
        model = llm_cfg.get("anthropic_model", "claude-opus-5-5")
        return AnthropicClient(model, max_tokens, llm_cfg.get("anthropic_effort", "medium"))
    raise ValueError(f"unknown llm provider: {provider}")
