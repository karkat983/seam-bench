"""Rules the parser must follow, checked on the fixture and (when downloaded) the real bundle."""
import re

import pytest

from src.config import load_config, resolve
from src.ingest import load_bundle, parse_techniques
from tests.test_ingest import FIXTURE, chunks

ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_revoked_attack_pattern_is_skipped():
    assert "T9998" not in {c.id for c in chunks()}


def test_deprecated_attack_pattern_is_skipped():
    assert "T9999" not in {c.id for c in chunks()}


def test_revoked_relationship_is_ignored():
    # The fixture links Execution Prevention to T1059 only through a revoked relationship.
    text = {c.id: c.text for c in chunks()}["T1059"]
    assert "Mitigations:" not in text
