#!/usr/bin/env python3
"""Materialize regular files from a newc archive for read-only ELF analysis."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path, PurePosixPath

import newc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing existing output directory: {args.output}")
    args.output.mkdir(parents=True)

    written = 0
    for entry in newc.read(args.cpio):
        if stat.S_IFMT(entry.mode) != stat.S_IFREG:
            continue
        relative = PurePosixPath(entry.name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"unsafe CPIO path: {entry.name}")
        target = args.output.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry.data)
        if target.read_bytes() != entry.data:
            raise SystemExit(f"materialized file changed: {entry.name}")
        written += 1
    print(f"materialized_regular_files={written}")


if __name__ == "__main__":
    main()
