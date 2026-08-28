#!/usr/bin/env python3
"""Extract and verify a gzip/newc ramdisk from an Android boot-v2 image."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import newc
from repack_boot_v2 import parse_boot_v2


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--raw-cpio", type=Path, required=True)
    parser.add_argument("--gzip-copy", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    parsed = parse_boot_v2(args.image)
    if parsed.ramdisk[:2] != b"\x1f\x8b":
        raise SystemExit("boot ramdisk is not gzip compressed")
    raw = gzip.decompress(parsed.ramdisk)
    args.raw_cpio.parent.mkdir(parents=True, exist_ok=True)
    args.raw_cpio.write_bytes(raw)
    entries = newc.read(args.raw_cpio)
    if len(entries) != len(newc.index(entries)):
        raise SystemExit("boot ramdisk contains duplicate CPIO paths")

    if args.gzip_copy is not None:
        args.gzip_copy.parent.mkdir(parents=True, exist_ok=True)
        args.gzip_copy.write_bytes(parsed.ramdisk)
    report = {
        "format": 1,
        "image_bytes": len(parsed.image),
        "image_sha256": sha256(parsed.image),
        "ramdisk_gzip_bytes": len(parsed.ramdisk),
        "ramdisk_gzip_sha256": sha256(parsed.ramdisk),
        "ramdisk_raw_bytes": len(raw),
        "ramdisk_raw_sha256": sha256(raw),
        "ramdisk_entries": len(entries),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
