# seam-bench

> Status: **in progress.** Sections marked *planned* are not built yet.

## Problem
Agents that read retrieved documents, tool outputs, and other agents' messages treat all of that text as trustworthy, so an instruction planted at any of those boundaries can redirect the agent's action. This matters because these boundaries are exactly where real systems mix untrusted data with instructions. See OWASP Top 10 for LLM Applications 2025, LLM01: Prompt Injection.

## Approach
*Planned.* A small security question-answering agent over public MITRE ATT&CK data, plus a harness that injects an attacker instruction at three seams (retrieved document, tool output, inter-agent message) and measures how often the agent's recommended action changes, with and without a provenance-tagging defence.

## Results
*Planned.* No numbers yet.

| Metric | Value |
|--------|-------|
| Task accuracy (clean) | — |
| ASR per seam, undefended | — |
| ASR per seam, defended | — |
| Blast radius | — |
| Utility cost | — |

## Run it
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/download_attack.py      # ~40 MB, into data/raw/ (gitignored)
python -m src.ingest                   # builds the local Chroma index
python -m src.query "how do attackers run PowerShell scripts"
pytest
```
The agent, injectors and evaluation are *planned*.

## What I learned
*Planned.*

## Notes
Public data only (MITRE ATT&CK Enterprise, STIX 2.1). Not affiliated with any employer. Built October 2026.

## Changelog
- Day 1: project scaffold and changelog.
