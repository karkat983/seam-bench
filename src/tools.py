"""Local tools the agent can call. Their output is the second kind of untrusted text (seam B)."""
import json
import pathlib
import re

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CveLookup:
    """Offline CVE lookup over data/cves.json (a stand-in for a vulnerability database)."""

    name = "cve_lookup"

    def __init__(self, path: pathlib.Path | str):
        records = json.loads(pathlib.Path(path).read_text())
        self._by_id = {r["id"].upper(): r for r in records}

    def lookup(self, cve_id: str) -> dict | None:
        """The record for one CVE ID (case-insensitive), or None if unknown."""
        return self._by_id.get(cve_id.strip().upper())
