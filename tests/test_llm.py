import pytest

from src.llm import OllamaClient, make_client


def test_ollama_options_are_deterministic_by_default():
    opts = OllamaClient("m").options()
    assert opts["temperature"] == 0
    assert opts["seed"] == 7


def test_seed_can_be_disabled():
    assert "seed" not in OllamaClient("m", seed=None).options()


def test_make_client_reads_config():
    client = make_client({"provider": "ollama", "model": "qwen2.5:7b-instruct", "temperature": 0, "seed": 3})
    assert client.model == "qwen2.5:7b-instruct"
    assert client.options()["seed"] == 3


def test_unknown_provider_rejected():
    with pytest.raises(ValueError):
        make_client({"provider": "nope", "model": "x"})


@pytest.mark.live
def test_short_answer_is_stable():
    # Short, constrained answers repeat; long free-text answers may not (docs/notes.md).
    client = make_client({"provider": "ollama", "model": "qwen2.5:7b-instruct"})
    a = client.complete("Answer with one word.", "Which ATT&CK tactic covers stealing passwords?")
    b = client.complete("Answer with one word.", "Which ATT&CK tactic covers stealing passwords?")
    assert a.text.strip().lower() == b.text.strip().lower()
