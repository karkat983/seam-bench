"""Scratch query against the technique index, to eyeball retrieval quality.

    python -m src.query "how do attackers run PowerShell scripts"
"""
import argparse

from src.config import load_config, resolve


def search(question: str, k: int) -> list[tuple[str, str, float]]:
    """Return (technique ID, name, distance) for the k nearest chunks."""
    import chromadb

    cfg = load_config()
    client = chromadb.PersistentClient(path=str(resolve(cfg, "chroma_dir")))
    col = client.get_collection(cfg["attack"]["collection"])
    res = col.query(query_texts=[question], n_results=k)
    return [
        (tid, meta["name"], dist)
        for tid, meta, dist in zip(res["ids"][0], res["metadatas"][0], res["distances"][0])
    ]


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
