#!/usr/bin/env python3
"""Fail closed unless every checked-in H.40 component matches its manifest."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(path: Path, record: dict, label: str) -> None:
    if not path.is_file():
        raise SystemExit(f"missing pinned input: {label}")
    data = path.read_bytes()
    if len(data) != record["bytes"] or sha256(data) != record["sha256"]:
        raise SystemExit(f"pinned input identity mismatch: {label}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prebuilt-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    for name, record in manifest["files"].items():
        verify(args.prebuilt_dir / name, record, name)
    for name, record in manifest["overlay"].items():
        verify(args.prebuilt_dir / "overlay" / name, record, name)
    repo_root = args.prebuilt_dir.parents[1]
    for name, record in manifest["configuration"].items():
        verify(repo_root / name, record, name)

    header = (args.prebuilt_dir / "boot-header-v2.bin").read_bytes()
    if header[:8] != b"ANDROID!":
        raise SystemExit("pinned header lacks Android boot magic")
    facts = {
        "page_size": struct.unpack_from("<I", header, 36)[0],
        "header_version": struct.unpack_from("<I", header, 40)[0],
        "header_size": struct.unpack_from("<I", header, 1644)[0],
    }
    expected = manifest["partition"]
    if facts != {
        "page_size": expected["page_size"],
        "header_version": expected["header_version"],
        "header_size": expected["header_size"],
    }:
        raise SystemExit(f"pinned boot header metadata mismatch: {facts}")
    raw = gzip.decompress((args.prebuilt_dir / "ramdisk-stock.cpio.gz").read_bytes())
    if (
        len(raw) != manifest["stock_ramdisk_raw_bytes"]
        or sha256(raw) != manifest["stock_ramdisk_raw_sha256"]
    ):
        raise SystemExit("pinned raw H.40 ramdisk identity mismatch")

    report = {
        "format": 1,
        "result": "PASS",
        "component_files": len(manifest["files"]),
        "configuration_files": len(manifest["configuration"]),
        "overlay_files": len(manifest["overlay"]),
        "stock_ramdisk_raw_bytes": len(raw),
        "stock_ramdisk_raw_sha256": sha256(raw),
        "boot_header": facts,
        "commondcs_provenance": manifest["overlay"][
            "system/lib64/vendor.oplus.hardware.commondcs@1.0.so"
        ]["source"],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
