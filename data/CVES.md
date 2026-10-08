# data/cves.json

A local, offline stand-in for a vulnerability database, used by the agent's `cve_lookup` tool.

- 30 well-known, public CVEs. IDs, names, products and years are public facts; the one-line
  summaries are written for this project.
- `technique` is this project's own mapping of each CVE to the ATT&CK technique an attacker
  uses it for (e.g. T1190 Exploit Public-Facing Application, T1068 Exploitation for Privilege
  Escalation). It is a reasonable reading, not an official MITRE or NVD mapping.
- Kept local on purpose: the tool output must be deterministic and controllable, because
  seam B injects into exactly this text.
