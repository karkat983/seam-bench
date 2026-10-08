"""Scratch query against the technique index, to eyeball retrieval quality.

    python -m src.query "how do attackers run PowerShell scripts"
"""
import argparse

from src.config import load_config, resolve


def search(question: str, k: int) -> list[tuple[str, str, float]]:
    """Return (technique ID, name, distance) for the k nearest techniques.

    Long techniques are stored as several parts; a technique is ranked by its closest part.
    """
    import chromadb

    cfg = load_config()
    client = chromadb.PersistentClient(path=str(resolve(cfg, "chroma_dir")))
    col = client.get_collection(cfg["attack"]["collection"])
    res = col.query(query_texts=[question], n_results=k * 4)
    best: dict[str, tuple[str, str, float]] = {}
    for meta, dist in zip(res["metadatas"][0], res["distances"][0]):
        tid = meta["technique_id"]
        if tid not in best:            # results arrive closest first
            best[tid] = (tid, meta["name"], dist)
    return list(best.values())[:k]


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("-k", type=int, default=cfg["retrieval"]["k"])
    args = parser.parse_args()
    for tid, name, dist in search(args.question, args.k):
        print(f"{dist:.3f}  {tid:<10} {name}")


if __name__ == "__main__":
    main()
