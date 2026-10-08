"""Scratch query against the technique index, to eyeball retrieval quality.

    python -m src.query "how do attackers run PowerShell scripts"
"""
import argparse

from src.config import load_config
from src.retriever import Retriever


def search(question: str, k: int) -> list[tuple[str, str, float]]:
    """Return (technique ID, name, distance) for the k nearest techniques."""
    return [(h["id"], h["name"], h["distance"]) for h in Retriever.from_config().retrieve(question, k)]


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
