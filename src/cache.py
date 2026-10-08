"""Disk cache for LLM calls, keyed by a hash of everything that determines the response.

Re-running an evaluation then costs no API calls or GPU time, and re-scoring a finished run
gives exactly the same answers even though the model itself is not bit-exact (docs/notes.md).
"""
import dataclasses
import hashlib
import json
import pathlib

from src.llm import LLMResponse


def cache_key(identity: dict, system: str, user: str) -> str:
    payload = json.dumps({"identity": identity, "system": system, "user": user}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class CachedClient:
    """Wraps any client with `complete(system, user)`; identical calls are served from disk."""

    def __init__(self, client, cache_dir: pathlib.Path | str):
        self.client = client
        self.cache_dir = pathlib.Path(cache_dir)
        self.hits = 0
        self.misses = 0

    def identity(self) -> dict:
        """Everything about the client that changes its output."""
        ident = {"class": type(self.client).__name__, "model": getattr(self.client, "model", None)}
        if hasattr(self.client, "options"):
            ident["options"] = self.client.options()
        return ident

    def _path(self, key: str) -> pathlib.Path:
        return self.cache_dir / key[:2] / f"{key}.json"

    def complete(self, system: str, user: str) -> LLMResponse:
        path = self._path(cache_key(self.identity(), system, user))
        if path.exists():
            self.hits += 1
            return LLMResponse(**json.loads(path.read_text()))
        self.misses += 1
        response = self.client.complete(system, user)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(dataclasses.asdict(response)))
        tmp.replace(path)
        return response
