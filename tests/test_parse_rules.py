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


def test_ids_have_attack_format_and_match_subtechnique_flag():
    for c in chunks():
        assert ATTACK_ID.match(c.id), c.id
        assert c.is_subtechnique == ("." in c.id)


@pytest.fixture(scope="module")
def real_chunks():
    path = resolve(load_config(), "stix_bundle")
    if not path.exists():
        pytest.skip("ATT&CK bundle not downloaded (python scripts/download_attack.py)")
    return parse_techniques(load_bundle(path))


def test_real_bundle_ids_have_attack_format(real_chunks):
    bad = [c.id for c in real_chunks if not ATTACK_ID.match(c.id)]
    assert bad == []
    assert all(c.is_subtechnique == ("." in c.id) for c in real_chunks)
    assert len({c.id for c in real_chunks}) == len(real_chunks)


def test_chunk_sections_appear_in_order():
    text = {c.id: c.text for c in chunks()}["T1059.001"]
    order = [
        "T1059.001: PowerShell",
        "Adversaries may abuse PowerShell",
        "Detection strategies:",
        "Data components:",
        "Mitigations:",
    ]
    positions = [text.index(marker) for marker in order]
    assert positions == sorted(positions)


def test_every_real_chunk_starts_with_id_and_name(real_chunks):
    for c in real_chunks:
        assert c.text.startswith(f"{c.id}: {c.name}")
    with_detection = sum("Detection strategies:" in c.text for c in real_chunks)
    assert with_detection == len(real_chunks)      # ATT&CK v19.2: every technique has a strategy
