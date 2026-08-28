#!/usr/bin/env python3
"""Create a deterministic gzip stream (level 9, empty name, mtime zero)."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.source.open("rb") as source, args.destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0) as compressed:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                compressed.write(chunk)

    with gzip.open(args.destination, "rb") as compressed:
        reconstructed = hashlib.sha256()
        total = 0
        for chunk in iter(lambda: compressed.read(1024 * 1024), b""):
            reconstructed.update(chunk)
            total += len(chunk)
    if reconstructed.hexdigest() != digest(args.source) or total != args.source.stat().st_size:
        raise SystemExit("gzip round-trip verification failed")

    print(
        json.dumps(
            {
                "source_bytes": args.source.stat().st_size,
                "source_sha256": digest(args.source),
                "output_bytes": args.destination.stat().st_size,
                "output_sha256": digest(args.destination),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
