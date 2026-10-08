"""Turn the ATT&CK STIX bundle into one text chunk per technique.

Each chunk holds the technique ID, name, description and detection text.
Revoked and deprecated objects are skipped.
"""
import json
import pathlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Chunk:
    id: str                 # e.g. T1059 or T1059.001
    name: str
    text: str
    is_subtechnique: bool
    stix_id: str


def load_bundle(path: pathlib.Path) -> dict:
    with open(path) as f:
        return json.load(f)


def attack_id(obj: dict) -> str | None:
    """Return the ATT&CK external ID (T####[.###]) of a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def to_chunk(obj: dict) -> Chunk | None:
    tid = attack_id(obj)
    if tid is None:
        return None
    name = obj.get("name", "").strip()
    description = obj.get("description", "").strip()
    detection = obj.get("x_mitre_detection", "").strip()
    parts = [f"{tid}: {name}", description]
    if detection:
        parts.append(f"Detection: {detection}")
    return Chunk(
        id=tid,
        name=name,
        text="\n\n".join(p for p in parts if p),
        is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
        stix_id=obj["id"],
    )


def parse_techniques(bundle: dict) -> list[Chunk]:
    """Return a chunk for every active attack-pattern in the bundle, sorted by ID."""
    chunks = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or not is_active(obj):
            continue
        chunk = to_chunk(obj)
        if chunk is not None:
            chunks.append(chunk)
    return sorted(chunks, key=lambda c: c.id)
