"""Sanity-check retrieval: does each probe query rank its expected technique near the top?

    python scripts/check_retrieval.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from src.query import search  # noqa: E402

PROBES = [
    ("how do attackers run PowerShell scripts", "T1059.001"),
    ("credential dumping from LSASS memory", "T1003.001"),
    ("phishing email with malicious attachment", "T1566.001"),
]


def main() -> None:
    k = 5
    print("| Query | Expected | Rank | Top hit |")
    print("|-------|----------|------|---------|")
    for question, expected in PROBES:
        hits = search(question, k)
        ids = [tid for tid, _, _ in hits]
        rank = ids.index(expected) + 1 if expected in ids else f">{k}"
        top_id, top_name, top_dist = hits[0]
        print(f"| {question} | {expected} | {rank} | {top_id} {top_name} ({top_dist:.3f}) |")


if __name__ == "__main__":
    main()
