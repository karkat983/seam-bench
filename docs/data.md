# Data

## MITRE ATT&CK Enterprise (knowledge base)

| Field | Value |
|-------|-------|
| Source | [mitre/cti](https://github.com/mitre/cti), `enterprise-attack/enterprise-attack.json` |
| Release | ATT&CK v19.2 (tag `ATT&CK-v19.2`, published 2026-08-05) |
| Format | STIX 2.0 bundle, ATT&CK spec 3.3.0 |
| Size | 47,953,963 bytes |
| SHA-256 | `f7eaf37fe53b50404084fe1fe67237278f7317e61c11ad550295722d13ede259` |
| Downloaded | 2026-10-09 |
| Licence | ATT&CK Terms of Use (free to use with attribution to MITRE) |

`scripts/download_attack.py` fetches the pinned tag and fails if the checksum differs.

### What is in the bundle

| STIX type | Count |
|-----------|-------|
| attack-pattern (techniques + sub-techniques) | 858 |
| ... of which revoked | 149 |
| ... of which deprecated | 12 |
| x-mitre-detection-strategy | 699 |
| x-mitre-analytic | 1,758 |
| x-mitre-data-component | 109 |
| course-of-action (mitigations) | 268 |
| relationship | 21,262 |

After dropping revoked and deprecated objects, **697 techniques** remain (222 top-level, 475 sub-techniques).

### Format change worth knowing

Older ATT&CK releases put free-text detection advice on each technique (`x_mitre_detection`).
In v19.2 that field is absent on every active technique. Detection guidance now lives in
`x-mitre-detection-strategy` objects linked to techniques by `detects` relationships; each
strategy references analytics, and each analytic lists the data components and log sources it
needs. Commits 013-014 rebuild per-technique detection text from that graph.

## Retrieval check

`scripts/check_retrieval.py` runs three probe queries against the index (Chroma default
embedding, all-MiniLM-L6-v2; squared L2 distance, lower is closer). Run on 2026-10-09:

| Query | Expected | Rank | Top hit |
|-------|----------|------|---------|
| how do attackers run PowerShell scripts | T1059.001 | 1 | T1059.001 PowerShell (0.635) |
| credential dumping from LSASS memory | T1003.001 | 1 | T1003.001 LSASS Memory (0.500) |
| phishing email with malicious attachment | T1566.001 | 1 | T1566.001 Spearphishing Attachment (0.803) |

All three expected techniques rank first. The next hits are sensible neighbours (e.g. LSA
Secrets and the parent OS Credential Dumping for the LSASS query), so the index is good enough
to build the agent on. This is a smoke test, not a retrieval benchmark.
