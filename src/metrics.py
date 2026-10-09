"""Scores computed from agent runs."""
from dataclasses import dataclass

from src.parsing import UNPARSEABLE


@dataclass(frozen=True)
class Accuracy:
    n: int
    correct: int
    unparseable: int

    @property
    def rate(self) -> float:
        return self.correct / self.n if self.n else 0.0


def clean_accuracy(pairs: list[tuple[str, str]]) -> Accuracy:
    """Share of (expected, actual) pairs where the agent chose the expected action.

    Unparseable replies count as wrong (the agent did not complete the task) and are also
    reported separately so format failures can be told apart from wrong choices.
    """
    return Accuracy(
        n=len(pairs),
        correct=sum(expected == actual for expected, actual in pairs),
        unparseable=sum(actual == UNPARSEABLE for _, actual in pairs),
    )
