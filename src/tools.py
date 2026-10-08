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

    def search(self, keyword: str, limit: int = 5) -> list[dict]:
        """Records whose ID, name, product or summary contains every word of `keyword`."""
        words = [w.lower() for w in keyword.split() if w]
        if not words:
            return []
        hits = []
        for record in self._by_id.values():
            haystack = " ".join(str(record[k]) for k in ("id", "name", "product", "summary")).lower()
            if all(w in haystack for w in words):
                hits.append(record)
        return sorted(hits, key=lambda r: r["id"])[:limit]


def find_cve_ids(text: str) -> list[str]:
    """CVE IDs mentioned in free text, upper-cased, in order of first appearance."""
    seen: list[str] = []
    for match in CVE_ID.findall(text):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen
