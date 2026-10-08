# Common tasks. Run `make help` for a list.
PYTHON ?= .venv/bin/python

.PHONY: help setup data ingest check lint test clean

help:      ## list targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

setup:     ## create .venv and install dependencies
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

data:      ## download the pinned ATT&CK bundle (checksum-verified)
	$(PYTHON) scripts/download_attack.py

ingest:    ## build the Chroma index (no-op if already current)
	$(PYTHON) -m src.ingest

check:     ## retrieval smoke test on three probe queries
	$(PYTHON) scripts/check_retrieval.py

lint:      ## ruff lint
	$(PYTHON) -m ruff check .

test:      ## offline unit tests (no LLM calls)
	$(PYTHON) -m pytest -q -m "not live"

clean:     ## delete the local index
	rm -rf data/chroma
