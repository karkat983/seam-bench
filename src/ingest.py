"""Turn the ATT&CK STIX bundle into one text chunk per technique.

Each chunk holds the technique ID, name, description and detection text.
Revoked and deprecated objects are skipped. Chunks are embedded with
Chroma's built-in local model and stored in a persistent collection.

    python -m src.ingest              # skips work if the index already matches the data
    python -m src.ingest --rebuild    # always drop and rebuild
"""
import argparse
import hashlib
import json
import pathlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

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
    platforms: tuple[str, ...] = ()  # e.g. ("Windows", "Linux")


def load_bundle(path: pathlib.Path) -> dict:
    with open(path) as f:
        return json.load(f)


def attack_id(obj: dict) -> str | None:
    """Return the ATT&CK external ID (T####[.###]) of a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


CITATION = re.compile(r"\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://)[^)]*\)")


def clean_text(text: str) -> str:
    """Drop ATT&CK citation markers and markdown link targets; tidy whitespace."""
    text = CITATION.sub("", text)
    text = MD_LINK.sub(r"\1", text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" +([.,;:])", r"\1", text)
    return text.strip()


def tactics_of(obj: dict) -> tuple[str, ...]:
    return tuple(
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    )


def is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


@dataclass
class BundleGraph:
    """Lookups over the relationship graph, keyed by technique STIX ID."""
    by_id: dict[str, dict]
    strategies: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    mitigations: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))


def build_graph(bundle: dict) -> BundleGraph:
    objects = bundle.get("objects", [])
    graph = BundleGraph(by_id={o["id"]: o for o in objects})
    for rel in objects:
        if rel.get("type") != "relationship" or not is_active(rel):
            continue
        source = graph.by_id.get(rel["source_ref"])
        if source is None or not is_active(source):
            continue
        # ATT&CK v18+: detection-strategy --detects--> attack-pattern
        if rel["relationship_type"] == "detects" and source["type"] == "x-mitre-detection-strategy":
            graph.strategies[rel["target_ref"]].append(source)
        elif rel["relationship_type"] == "mitigates" and source["type"] == "course-of-action":
            graph.mitigations[rel["target_ref"]].append(source)
    return graph


def data_components(graph: BundleGraph, technique_id: str) -> list[str]:
    """Names of the data components that the technique's analytics read from."""
    names = set()
    for strategy in graph.strategies.get(technique_id, []):
        for analytic_id in strategy.get("x_mitre_analytic_refs", []):
            analytic = graph.by_id.get(analytic_id)
            if analytic is None or not is_active(analytic):
                continue
            for source in analytic.get("x_mitre_log_source_references", []):
                component = graph.by_id.get(source.get("x_mitre_data_component_ref", ""))
                if component is not None and is_active(component):
                    names.add(component["name"])
    return sorted(names)


def to_chunk(obj: dict, graph: BundleGraph | None = None) -> Chunk | None:
    tid = attack_id(obj)
    if tid is None:
        return None
    name = obj.get("name", "").strip()
    description = clean_text(obj.get("description", ""))
    # Pre-v18 bundles carry free-text detection advice on the technique itself.
    detection = clean_text(obj.get("x_mitre_detection", ""))
    parts = [f"{tid}: {name}", description]
    if detection:
        parts.append(f"Detection: {detection}")
    strategies = sorted(s["name"] for s in graph.strategies.get(obj["id"], [])) if graph else []
    if strategies:
        parts.append("Detection strategies: " + "; ".join(strategies))
    components = data_components(graph, obj["id"]) if graph else []
    if components:
        parts.append("Data components: " + ", ".join(components))
    mitigations = sorted({m["name"] for m in graph.mitigations.get(obj["id"], [])}) if graph else []
    if mitigations:
        parts.append("Mitigations: " + ", ".join(mitigations))
    return Chunk(
        id=tid,
        name=name,
        text="\n\n".join(p for p in parts if p),
        is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
        stix_id=obj["id"],
        tactics=tactics_of(obj),
        platforms=tuple(obj.get("x_mitre_platforms", [])),
    )


def part_id(technique_id: str, part: int) -> str:
    """Chroma ID of one part of a technique, e.g. T1003.001#2."""
    return f"{technique_id}#{part}"


def technique_of(pid: str) -> str:
    return pid.split("#", 1)[0]


def split_text(text: str, max_chars: int, overlap: int) -> list[str]:
    """Split text into pieces of at most max_chars, overlapping by about `overlap` chars.

    Cuts prefer a paragraph break, then a sentence end, then a space, so words stay whole.
    """
    if max_chars <= overlap:
        raise ValueError("max_chars must be larger than overlap")
    pieces, start = [], 0
    while len(text) - start > max_chars:
        window = text[start:start + max_chars]
        cut = max(window.rfind("\n\n"), window.rfind(". ") + 1, 0)
        if cut < max_chars // 2:
            cut = window.rfind(" ")
        if cut <= overlap:
            cut = max_chars
        pieces.append(text[start:start + cut].strip())
        next_start = start + cut - overlap
        # Restart on a word boundary inside the overlap.
        space = text.find(" ", next_start)
        start = space + 1 if 0 <= space < start + cut else next_start
    pieces.append(text[start:].strip())
    return [p for p in pieces if p]


def parse_techniques(bundle: dict) -> list[Chunk]:
    """Return a chunk for every active attack-pattern in the bundle, sorted by ID."""
    graph = build_graph(bundle)
    chunks = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or not is_active(obj):
            continue
        chunk = to_chunk(obj, graph)
        if chunk is not None:
            chunks.append(chunk)
    return sorted(chunks, key=lambda c: c.id)


def fingerprint(parts: list[tuple]) -> str:
    """Hash of every part ID and text, so an unchanged index can be detected."""
    sha = hashlib.sha256()
    for pid, text, _, _ in parts:
        sha.update(pid.encode())
        sha.update(b"\0")
        sha.update(text.encode())
        sha.update(b"\0")
    return sha.hexdigest()


def build_index(
    chunks: list[Chunk],
    chroma_dir: pathlib.Path,
    collection: str,
    max_chars: int = 1000,
    overlap: int = 150,
    rebuild: bool = False,
):
    """Create the collection from the chunks (split into parts) unless it is already current.

    Returns (collection, built) where built is False when the existing index was reused.
    """
    import chromadb  # imported here so parsing works without chromadb installed

    parts = []
    for c in chunks:
        pieces = split_text(c.text, max_chars, overlap)
        for i, text in enumerate(pieces):
            header = f"{c.id}: {c.name} (continued)\n\n" if i else ""
            meta = {"part": i, "n_parts": len(pieces)}
            parts.append((part_id(c.id, i), header + text, c, meta))

    digest = fingerprint(parts)
    client = chromadb.PersistentClient(path=str(chroma_dir))
    if collection in [c.name for c in client.list_collections()]:
        existing = client.get_collection(collection)
        if not rebuild and (existing.metadata or {}).get("fingerprint") == digest:
            return existing, False
        client.delete_collection(collection)
    col = client.create_collection(collection, metadata={"fingerprint": digest})
    for i in range(0, len(parts), BATCH_SIZE):
        batch = parts[i:i + BATCH_SIZE]
        col.add(
            ids=[pid for pid, _, _, _ in batch],
            documents=[text for _, text, _, _ in batch],
            metadatas=[
                {
                    "technique_id": c.id,
                    "name": c.name,
                    "is_subtechnique": c.is_subtechnique,
                    "stix_id": c.stix_id,
                    "tactics": ",".join(c.tactics),
                    "platforms": ",".join(c.platforms),
                    **meta,
                }
                for _, _, c, meta in batch
            ],
        )
    return col, True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rebuild", action="store_true", help="rebuild even if the index is current")
    args = parser.parse_args()

    cfg = load_config()
    chunks = parse_techniques(load_bundle(resolve(cfg, "stix_bundle")))
    subs = sum(c.is_subtechnique for c in chunks)
    print(f"parsed {len(chunks)} techniques ({len(chunks) - subs} top-level, {subs} sub-techniques)")
    col, built = build_index(
        chunks, resolve(cfg, "chroma_dir"), cfg["attack"]["collection"],
        cfg["chunking"]["max_chars"], cfg["chunking"]["overlap_chars"], rebuild=args.rebuild,
    )
    verb = "indexed" if built else "index up to date:"
    print(f"{verb} {col.count()} parts from {len(chunks)} techniques in {cfg['attack']['collection']}")


if __name__ == "__main__":
    main()
