from src.cache import CachedClient, cache_key
from src.llm import LLMResponse


class CountingClient:
    model = "fake-1"

    def __init__(self):
        self.calls = 0

    def options(self):
        return {"temperature": 0}

    def complete(self, system, user):
        self.calls += 1
        text = f"answer {self.calls} to {user}"
        return LLMResponse(text=text, model=self.model, input_tokens=3, output_tokens=2)


def test_identical_call_is_served_from_disk(tmp_path):
    inner = CountingClient()
    cached = CachedClient(inner, tmp_path)
    first = cached.complete("sys", "q")
    second = cached.complete("sys", "q")
    assert inner.calls == 1
    assert first == second
    assert (cached.hits, cached.misses) == (1, 1)


def test_cache_survives_a_new_client_instance(tmp_path):
    CachedClient(CountingClient(), tmp_path).complete("sys", "q")
    fresh = CountingClient()
    CachedClient(fresh, tmp_path).complete("sys", "q")
    assert fresh.calls == 0


def test_any_input_change_misses(tmp_path):
    inner = CountingClient()
    cached = CachedClient(inner, tmp_path)
    cached.complete("sys", "q")
    cached.complete("sys2", "q")
    cached.complete("sys", "q2")
    assert inner.calls == 3


def test_key_depends_on_model_and_options():
    base = cache_key({"model": "a", "options": {"seed": 1}}, "s", "u")
    assert base != cache_key({"model": "b", "options": {"seed": 1}}, "s", "u")
    assert base != cache_key({"model": "a", "options": {"seed": 2}}, "s", "u")


def test_cache_hit_never_reaches_the_model(tmp_path):
    # Production wiring: cache outside, meter inside, so the meter only sees real calls.
    from src.fake_llm import FakeLLM
    from src.usage import MeteredClient

    fake = FakeLLM().on("q", "answer")
    meter = MeteredClient(fake)
    client = CachedClient(meter, tmp_path)
    for _ in range(5):
        assert client.complete("sys", "q").text == "answer"
    assert len(fake.calls) == 1
    assert meter.by_model["fake-llm"].calls == 1
    assert (client.hits, client.misses) == (4, 1)
