"""Retrieve ATT&CK techniques for a question from the local Chroma index."""
import pathlib
from dataclasses import dataclass

from src.config import load_config, resolve


@dataclass(frozen=True)
class Hit:
    id: str            # technique ID, e.g. T1003.001
    name: str
    text: str          # text of the best-matching part
    score: float       # Chroma distance; lower is closer
    source: str        # provenance label, e.g. "retrieval:T1003.001#0"


class Retriever:
    """Top-k technique search. A technique stored as several parts is ranked by its best part."""

    def __init__(self, chroma_dir: pathlib.Path, collection: str, k: int):
        import chromadb

        self.k = k
        self._col = chromadb.PersistentClient(path=str(chroma_dir)).get_collection(collection)

    @classmethod
    def from_config(cls, cfg: dict | None = None) -> "Retriever":
        cfg = cfg or load_config()
        return cls(resolve(cfg, "chroma_dir"), cfg["attack"]["collection"], cfg["retrieval"]["k"])

    def retrieve(self, question: str, k: int | None = None) -> list[Hit]:
        k = k or self.k
        res = self._col.query(query_texts=[question], n_results=k * 4)
        best: dict[str, Hit] = {}
        for pid, doc, meta, dist in zip(
            res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0], strict=True
        ):
            tid = meta["technique_id"]
            if tid not in best:            # results arrive closest first
                best[tid] = Hit(id=tid, name=meta["name"], text=doc, score=dist, source=f"retrieval:{pid}")
        return list(best.values())[:k]
