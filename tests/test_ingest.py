import pathlib

from src.ingest import attack_id, clean_text, load_bundle, parse_techniques

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "mini_stix.json"


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
