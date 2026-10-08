import pathlib

import pytest

from src.ingest import load_bundle, parse_techniques

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MINI_STIX = FIXTURES / "mini_stix.json"


@pytest.fixture(scope="session")
def mini_bundle() -> dict:
    return load_bundle(MINI_STIX)


@pytest.fixture(scope="session")
def mini_chunks(mini_bundle):
    return parse_techniques(mini_bundle)
