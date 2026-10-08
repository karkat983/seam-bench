import pytest

from src.ingest import Chunk, build_index

chromadb = pytest.importorskip("chromadb")

TECHNIQUES = [
    ("T1059.001", "PowerShell", "Adversaries abuse PowerShell commands and scripts to execute code."),
    ("T1003.001", "LSASS Memory", "Adversaries dump credentials from the memory of the LSASS process."),
    ("T1566.001", "Spearphishing Attachment", "Adversaries send emails with a malicious file attached."),
    ("T1021.001", "Remote Desktop Protocol", "Adversaries log in to remote hosts over RDP to move."),
    ("T1486", "Data Encrypted for Impact", "Adversaries encrypt files on many systems to demand a ransom."),
]


@pytest.fixture(scope="module")
def retriever(tmp_path_factory):
    from src.retriever import Retriever

    path = tmp_path_factory.mktemp("chroma")
    chunks = [Chunk(id=t, name=n, text=f"{t}: {n}\n\n{d}", is_subtechnique="." in t, stix_id=f"x--{t}")
              for t, n, d in TECHNIQUES]
    build_index(chunks, path, "fixture_techniques")
    return Retriever(path, "fixture_techniques", k=3)


@pytest.mark.parametrize("question, expected", [
    ("powershell script execution", "T1059.001"),
    ("dumping passwords from lsass", "T1003.001"),
    ("malicious email attachment", "T1566.001"),
    ("RDP lateral movement", "T1021.001"),
    ("ransomware encrypting files", "T1486"),
])
def test_top_hit_is_expected_technique(retriever, question, expected):
    assert retriever.retrieve(question)[0].id == expected


def test_returns_k_distinct_hits_sorted_by_score(retriever):
    hits = retriever.retrieve("adversaries", k=4)
    assert len(hits) == 4
    assert len({h.id for h in hits}) == 4
    assert [h.score for h in hits] == sorted(h.score for h in hits)


def test_hits_carry_provenance(retriever):
    hit = retriever.retrieve("ransomware")[0]
    assert hit.source == "retrieval:T1486#0"
    assert hit.text.startswith("T1486: Data Encrypted for Impact")
