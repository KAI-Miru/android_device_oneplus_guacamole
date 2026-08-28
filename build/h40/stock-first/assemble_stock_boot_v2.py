#!/usr/bin/env python3
"""Assemble the checked-in ColorOS H.40 boot-v2 payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from repack_boot_v2 import align, parse_boot_v2


COMPONENTS = (
    ("kernel", "kernel"),
    ("ramdisk", "ramdisk-stock.cpio.gz"),
    ("recovery_dtbo", "recovery-dtbo.img"),
    ("dtb", "dtb.img"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_record(name: str, data: bytes, record: dict) -> None:
    if len(data) != record["bytes"] or sha256(data) != record["sha256"]:
        raise SystemExit(f"H.40 prebuilt identity mismatch: {name}")


def append_padded(output: bytearray, data: bytes, page_size: int) -> None:
    output.extend(data)
    output.extend(b"\0" * (align(len(data), page_size) - len(data)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prebuilt-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    header = (args.prebuilt_dir / "boot-header-v2.bin").read_bytes()
    verify_record("boot-header-v2.bin", header, manifest["files"]["boot-header-v2.bin"])
    if len(header) != 4096 or header[:8] != b"ANDROID!":
        raise SystemExit("invalid H.40 boot header page")
    page_size = struct.unpack_from("<I", header, 36)[0]
    header_version = struct.unpack_from("<I", header, 40)[0]
    header_size = struct.unpack_from("<I", header, 1644)[0]
    if (page_size, header_version, header_size) != (4096, 2, 1660):
        raise SystemExit("H.40 boot is not the pinned 4096-byte boot-v2 format")

    values = {}
    for label, filename in COMPONENTS:
        data = (args.prebuilt_dir / filename).read_bytes()
        verify_record(filename, data, manifest["files"][filename])
        values[label] = data
    values["second"] = b""

    header_sizes = {
        "kernel": struct.unpack_from("<I", header, 8)[0],
        "ramdisk": struct.unpack_from("<I", header, 16)[0],
        "second": struct.unpack_from("<I", header, 24)[0],
        "recovery_dtbo": struct.unpack_from("<I", header, 1632)[0],
        "dtb": struct.unpack_from("<I", header, 1648)[0],
    }
    for name, expected in header_sizes.items():
        if len(values[name]) != expected:
            raise SystemExit(f"header size mismatch for {name}")

    output = bytearray(header)
    for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb"):
        append_padded(output, values[name], page_size)
    if len(output) != manifest["stock_boot_payload_bytes"]:
        raise SystemExit("assembled stock payload has the wrong size")
    if sha256(output) != manifest["stock_boot_payload_sha256"]:
        raise SystemExit("assembled stock payload has the wrong digest")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    parsed = parse_boot_v2(args.output)
    for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb"):
        if getattr(parsed, name) != values[name]:
            raise SystemExit(f"round-trip mismatch for {name}")

    report = {
        "format": 1,
        "result": "PASS",
        "source_stock_boot_sha256": manifest["source_stock_boot_sha256"],
        "assembled_boot_payload_bytes": len(output),
        "assembled_boot_payload_sha256": sha256(output),
        "components": {
            name: {"bytes": len(values[name]), "sha256": sha256(values[name])}
            for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb")
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
