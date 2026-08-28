#!/usr/bin/env python3
"""Merge ordered newc overlays into a base archive without filesystem extraction."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import newc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--overlay", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if not args.overlay:
        raise SystemExit("at least one --overlay is required")

    merged = list(newc.read(args.base))
    positions = {entry.name: number for number, entry in enumerate(merged)}
    if len(positions) != len(merged):
        raise SystemExit("base CPIO contains duplicate paths")
    added = replaced = 0
    for overlay_path in args.overlay:
        overlay = newc.read(overlay_path)
        if len(overlay) != len(newc.index(overlay)):
            raise SystemExit(f"overlay contains duplicate paths: {overlay_path}")
        for entry in overlay:
            if entry.name in positions:
                merged[positions[entry.name]] = entry
                replaced += 1
            else:
                positions[entry.name] = len(merged)
                merged.append(entry)
                added += 1

    newc.write(args.output, merged)
    roundtrip = newc.read(args.output)
    if roundtrip != merged:
        raise SystemExit("merged CPIO changed on round-trip")
    report = {
        "format": 1,
        "base_sha256": sha256(args.base),
        "overlay_sha256": [sha256(path) for path in args.overlay],
        "entries": len(merged),
        "overlay_added": added,
        "overlay_replaced": replaced,
        "output_bytes": args.output.stat().st_size,
        "output_sha256": sha256(args.output),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
