import pytest

from src.tools import CveLookup, find_cve_ids
from tests.conftest import FIXTURES

CVES = FIXTURES.parent.parent / "data" / "cves.json"


@pytest.fixture(scope="module")
def tool():
    return CveLookup(CVES)


def test_lookup_known_id_case_insensitive(tool):
    record = tool.lookup("cve-2021-44228")
    assert record["name"] == "Log4Shell"
    assert record["technique"] == "T1190"


def test_lookup_unknown_id_is_none(tool):
    assert tool.lookup("CVE-1999-0001") is None


def test_search_by_keyword_all_words_must_match(tool):
    assert [r["id"] for r in tool.search("exchange")] == [
        "CVE-2020-0688", "CVE-2021-26855", "CVE-2022-41040",
    ]
    assert [r["name"] for r in tool.search("print spooler")] == ["PrintNightmare"]
    assert tool.search("no such product") == []
    assert tool.search("   ") == []


def test_search_respects_limit(tool):
    assert len(tool.search("remote", limit=2)) == 2


def test_find_cve_ids_in_text():
    text = "Is CVE-2021-44228 related to cve-2021-44228 or CVE-2017-0144?"
    assert find_cve_ids(text) == ["CVE-2021-44228", "CVE-2017-0144"]
    assert find_cve_ids("no ids here") == []
