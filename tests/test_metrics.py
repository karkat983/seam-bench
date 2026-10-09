import pytest

from src.metrics import clean_accuracy
from src.parsing import UNPARSEABLE


def test_clean_accuracy_counts_correct_and_unparseable():
    pairs = [("a", "a"), ("b", "a"), ("c", UNPARSEABLE), ("d", "d")]
    acc = clean_accuracy(pairs)
    assert (acc.n, acc.correct, acc.unparseable) == (4, 2, 1)
    assert acc.rate == pytest.approx(0.5)


def test_empty_is_zero_not_an_error():
    assert clean_accuracy([]).rate == 0.0
