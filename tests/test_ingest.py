import pytest

from src.ingest import (
    attack_id, clean_text, ingest_stats, load_bundle, parse_techniques, part_id, split_text,
    technique_of,
)

from tests.conftest import MINI_STIX as FIXTURE


def chunks():
    return parse_techniques(load_bundle(FIXTURE))


def test_only_active_attack_patterns_are_kept():
    assert [c.id for c in chunks()] == ["T1059", "T1059.001"]


def test_subtechnique_flag():
    flags = {c.id: c.is_subtechnique for c in chunks()}
    assert flags == {"T1059": False, "T1059.001": True}


def test_chunk_text_has_id_name_description_and_detection():
    text = chunks()[0].text
    assert text.startswith("T1059: Command and Scripting Interpreter")
    assert "abuse command and script interpreters" in text
    assert "Detection: Monitor command-line arguments" in text


def test_missing_detection_is_omitted():
    assert "Detection:" not in chunks()[1].text


def test_attack_id_ignores_other_sources():
    obj = {"external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}]}
    assert attack_id(obj) is None


def test_tactics_come_from_mitre_attack_kill_chain_only():
    tactics = {c.id: c.tactics for c in chunks()}
    assert tactics == {"T1059": ("execution",), "T1059.001": ("execution",)}


def test_platforms_are_kept():
    platforms = {c.id: c.platforms for c in chunks()}
    assert platforms == {"T1059": ("Windows", "Linux", "macOS"), "T1059.001": ("Windows",)}


def test_detection_strategies_are_attached_and_deprecated_ones_skipped():
    text = {c.id: c.text for c in chunks()}["T1059.001"]
    assert "Detection strategies: Detect suspicious PowerShell execution" in text
    assert "Old deprecated strategy" not in text


def test_data_components_come_from_strategy_analytics():
    text = {c.id: c.text for c in chunks()}["T1059.001"]
    assert "Data components: Process Creation, Script Execution" in text


def test_mitigations_attached_and_revoked_ones_skipped():
    text = {c.id: c.text for c in chunks()}["T1059.001"]
    assert "Mitigations: Execution Prevention" in text
    assert "Retired Mitigation" not in text


def test_clean_text_drops_citations_and_link_targets():
    raw = ("Adversaries may use [PowerShell](https://attack.mitre.org/techniques/T1059/001) "
           "to run code.(Citation: Some Report 2020)  Extra   spaces.\n\n\n\nNext paragraph.")
    assert clean_text(raw) == "Adversaries may use PowerShell to run code. Extra spaces.\n\nNext paragraph."


def test_short_text_is_not_split():
    assert split_text("short text", max_chars=100, overlap=10) == ["short text"]


def test_split_respects_max_and_overlaps():
    text = " ".join(f"Sentence number {i} is here." for i in range(60))
    pieces = split_text(text, max_chars=200, overlap=40)
    assert len(pieces) > 1
    assert all(len(p) <= 200 for p in pieces)
    for a, b in zip(pieces, pieces[1:]):
        assert b.split()[0] in a          # the next piece starts inside the previous one


def test_split_covers_every_word():
    text = " ".join(f"w{i}" for i in range(500))
    pieces = split_text(text, max_chars=120, overlap=20)
    assert set(" ".join(pieces).split()) == set(text.split())


def test_split_rejects_bad_settings():
    with pytest.raises(ValueError):
        split_text("abc", max_chars=10, overlap=10)


def test_part_id_round_trip():
    assert part_id("T1003.001", 2) == "T1003.001#2"
    assert technique_of("T1003.001#2") == "T1003.001"


def test_build_index_reuses_current_index(tmp_path):
    pytest.importorskip("chromadb")
    from src.ingest import build_index

    col, built = build_index(chunks(), tmp_path, "test_col", max_chars=80, overlap=10)
    assert built and col.count() > len(chunks())          # long texts were split
    _, built_again = build_index(chunks(), tmp_path, "test_col", max_chars=80, overlap=10)
    assert not built_again
    _, forced = build_index(chunks(), tmp_path, "test_col", max_chars=80, overlap=10, rebuild=True)
    assert forced


def test_ingest_stats_counts_kept_and_skipped():
    stats = ingest_stats(load_bundle(FIXTURE))
    assert stats == {"attack_patterns": 4, "revoked": 1, "deprecated": 1, "no_attack_id": 0, "kept": 2}
