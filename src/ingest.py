"""Turn the ATT&CK STIX bundle into one text chunk per technique.

Each chunk holds the technique ID, name, description and detection text.
Revoked and deprecated objects are skipped. Chunks are embedded with
Chroma's built-in local model and stored in a persistent collection.

    python -m src.ingest
"""
import json
import pathlib
from dataclasses import dataclass

from src.config import load_config, resolve

BATCH_SIZE = 500


@dataclass(frozen=True)
class Chunk:
    id: str                 # e.g. T1059 or T1059.001
    name: str
    text: str
    is_subtechnique: bool
    stix_id: str
    tactics: tuple[str, ...] = ()   # ATT&CK kill-chain phases, e.g. ("credential-access",)


def load_bundle(path: pathlib.Path) -> dict:
    with open(path) as f:
        return json.load(f)


def attack_id(obj: dict) -> str | None:
    """Return the ATT&CK external ID (T####[.###]) of a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def tactics_of(obj: dict) -> tuple[str, ...]:
    return tuple(
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    )


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
        tactics=tactics_of(obj),
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


def build_index(chunks: list[Chunk], chroma_dir: pathlib.Path, collection: str):
    """(Re)create the collection and add every chunk. Returns the collection."""
    import chromadb  # imported here so parsing works without chromadb installed

    client = chromadb.PersistentClient(path=str(chroma_dir))
    if collection in [c.name for c in client.list_collections()]:
        client.delete_collection(collection)
    col = client.create_collection(collection)
    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i:i + BATCH_SIZE]
        col.add(
            ids=[c.id for c in batch],
            documents=[c.text for c in batch],
            metadatas=[
                {
                    "name": c.name,
                    "is_subtechnique": c.is_subtechnique,
                    "stix_id": c.stix_id,
                    "tactics": ",".join(c.tactics),
                }
                for c in batch
            ],
        )
    return col


def main() -> None:
    cfg = load_config()
    chunks = parse_techniques(load_bundle(resolve(cfg, "stix_bundle")))
    subs = sum(c.is_subtechnique for c in chunks)
    print(f"parsed {len(chunks)} techniques ({len(chunks) - subs} top-level, {subs} sub-techniques)")
    col = build_index(chunks, resolve(cfg, "chroma_dir"), cfg["attack"]["collection"])
    print(f"indexed {col.count()} chunks into {cfg['attack']['collection']}")


if __name__ == "__main__":
    main()
