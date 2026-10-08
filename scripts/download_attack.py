"""Download the public MITRE ATT&CK Enterprise STIX bundle into data/raw/.

The bundle is large (~40 MB) and is gitignored. Run this once:

    python scripts/download_attack.py
"""
import argparse
import hashlib
import pathlib
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def download(url: str, dest: pathlib.Path) -> str:
    """Stream url to dest and return the file's SHA-256."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256()
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url) as resp, open(tmp, "wb") as out:
        while chunk := resp.read(1 << 20):
            sha.update(chunk)
            out.write(chunk)
    tmp.replace(dest)
    return sha.hexdigest()


def main() -> None:
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=cfg["attack"]["stix_url"])
    parser.add_argument("--out", default=str(ROOT / cfg["paths"]["stix_bundle"]))
    args = parser.parse_args()

    dest = pathlib.Path(args.out)
    digest = download(args.url, dest)
    print(f"saved {dest} ({dest.stat().st_size:,} bytes)")
    print(f"sha256 {digest}")


if __name__ == "__main__":
    main()
