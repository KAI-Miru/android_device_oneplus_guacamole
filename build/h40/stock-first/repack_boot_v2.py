#!/usr/bin/env python3
"""Repack an Android boot header-v2 image with a replacement ramdisk.

The stock header page and every non-ramdisk component are retained.  AVB data is
deliberately omitted; add and verify a fresh hash footer with avbtool afterward.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


BOOT_MAGIC = b"ANDROID!"
AVB_FOOTER_MAGIC = b"AVBf"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, page_size: int) -> int:
    return (value + page_size - 1) // page_size * page_size


@dataclass(frozen=True)
class BootV2:
    image: bytes
    header_page: bytes
    page_size: int
    kernel: bytes
    ramdisk: bytes
    second: bytes
    recovery_dtbo: bytes
    dtb: bytes
    original_image_size: int


def parse_boot_v2(path: Path) -> BootV2:
    image = path.read_bytes()
    if image[:8] != BOOT_MAGIC:
        raise SystemExit(f"{path} is not an Android boot image")

    kernel_size = struct.unpack_from("<I", image, 8)[0]
    ramdisk_size = struct.unpack_from("<I", image, 16)[0]
    second_size = struct.unpack_from("<I", image, 24)[0]
    page_size = struct.unpack_from("<I", image, 36)[0]
    header_version = struct.unpack_from("<I", image, 40)[0]
    recovery_dtbo_size = struct.unpack_from("<I", image, 1632)[0]
    recovery_dtbo_offset = struct.unpack_from("<Q", image, 1636)[0]
    header_size = struct.unpack_from("<I", image, 1644)[0]
    dtb_size = struct.unpack_from("<I", image, 1648)[0]

    if header_version != 2 or header_size != 1660:
        raise SystemExit(
            f"expected Android boot header v2/1660, got version={header_version}, size={header_size}"
        )
    if page_size < 2048 or page_size > 65536 or page_size & (page_size - 1):
        raise SystemExit(f"invalid boot page size: {page_size}")
    if len(image) < page_size:
        raise SystemExit("truncated boot header page")

    offset = page_size
    kernel = image[offset : offset + kernel_size]
    offset += align(kernel_size, page_size)
    ramdisk = image[offset : offset + ramdisk_size]
    offset += align(ramdisk_size, page_size)
    second = image[offset : offset + second_size]
    offset += align(second_size, page_size)
    if recovery_dtbo_offset != offset:
        raise SystemExit(
            f"recovery-DTBO offset mismatch: header={recovery_dtbo_offset}, calculated={offset}"
        )
    recovery_dtbo = image[offset : offset + recovery_dtbo_size]
    offset += align(recovery_dtbo_size, page_size)
    dtb = image[offset : offset + dtb_size]
    component_end = offset + align(dtb_size, page_size)

    for label, data, expected in (
        ("kernel", kernel, kernel_size),
        ("ramdisk", ramdisk, ramdisk_size),
        ("second", second, second_size),
        ("recovery_dtbo", recovery_dtbo, recovery_dtbo_size),
        ("dtb", dtb, dtb_size),
    ):
        if len(data) != expected:
            raise SystemExit(f"truncated {label}: expected {expected}, got {len(data)}")

    original_image_size = component_end
    if len(image) >= 64 and image[-64:-60] == AVB_FOOTER_MAGIC:
        _magic, major, minor, avb_original, vbmeta_offset, vbmeta_size, _reserved = struct.unpack(
            ">4sIIQQQ28s", image[-64:]
        )
        if (major, minor) != (1, 0):
            raise SystemExit(f"unsupported AVB footer version: {major}.{minor}")
        if avb_original != component_end:
            raise SystemExit(
                f"AVB original image size {avb_original} does not match boot components {component_end}"
            )
        if vbmeta_offset < avb_original or vbmeta_offset + vbmeta_size > len(image) - 64:
            raise SystemExit("invalid AVB vbmeta bounds")
        original_image_size = avb_original
    elif component_end != len(image):
        raise SystemExit(
            f"unexpected trailing data without AVB footer: component_end={component_end}, image={len(image)}"
        )

    return BootV2(
        image=image,
        header_page=image[:page_size],
        page_size=page_size,
        kernel=kernel,
        ramdisk=ramdisk,
        second=second,
        recovery_dtbo=recovery_dtbo,
        dtb=dtb,
        original_image_size=original_image_size,
    )


def append_padded(output: bytearray, component: bytes, page_size: int) -> None:
    output.extend(component)
    output.extend(b"\0" * (align(len(component), page_size) - len(component)))


def boot_id(components: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha1()
    for component in components:
        digest.update(component)
        digest.update(struct.pack("<I", len(component)))
    return digest.digest() + b"\0" * 12


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-boot", type=Path, required=True)
    parser.add_argument("--ramdisk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    stock = parse_boot_v2(args.stock_boot)
    replacement = args.ramdisk.read_bytes()
    if replacement[:2] != b"\x1f\x8b":
        raise SystemExit("replacement ramdisk is not gzip-compressed")

    header = bytearray(stock.header_page)
    struct.pack_into("<I", header, 16, len(replacement))
    recovery_offset = (
        stock.page_size
        + align(len(stock.kernel), stock.page_size)
        + align(len(replacement), stock.page_size)
        + align(len(stock.second), stock.page_size)
    )
    struct.pack_into("<Q", header, 1636, recovery_offset)
    image_id = boot_id(
        (stock.kernel, replacement, stock.second, stock.recovery_dtbo, stock.dtb)
    )
    header[576:608] = image_id

    output = bytearray(header)
    for component in (
        stock.kernel,
        replacement,
        stock.second,
        stock.recovery_dtbo,
        stock.dtb,
    ):
        append_padded(output, component, stock.page_size)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    rebuilt = parse_boot_v2(args.output)
    if rebuilt.ramdisk != replacement:
        raise SystemExit("repacked ramdisk differs from requested payload")
    for label in ("kernel", "second", "recovery_dtbo", "dtb"):
        if getattr(rebuilt, label) != getattr(stock, label):
            raise SystemExit(f"repacked {label} differs from stock")

    report = {
        "format": 1,
        "header_version": 2,
        "header_size": 1660,
        "page_size": stock.page_size,
        "stock_boot_bytes": len(stock.image),
        "stock_boot_sha256": sha256(stock.image),
        "stock_original_image_bytes": stock.original_image_size,
        "repacked_image_bytes_before_avb": len(output),
        "repacked_image_sha256_before_avb": sha256(output),
        "boot_id_sha1": image_id[:20].hex(),
        "components": {
            "kernel": {"bytes": len(stock.kernel), "sha256": sha256(stock.kernel)},
            "ramdisk": {"bytes": len(replacement), "sha256": sha256(replacement)},
            "second": {"bytes": len(stock.second), "sha256": sha256(stock.second)},
            "recovery_dtbo": {
                "bytes": len(stock.recovery_dtbo),
                "sha256": sha256(stock.recovery_dtbo),
            },
            "dtb": {"bytes": len(stock.dtb), "sha256": sha256(stock.dtb)},
        },
        "checks": {
            "stock_header_v2": True,
            "ramdisk_exact_requested_payload": True,
            "kernel_exact_stock": True,
            "second_exact_stock": True,
            "recovery_dtbo_exact_stock": True,
            "dtb_exact_stock": True,
            "boot_id_regenerated": True,
            "avb_footer_intentionally_absent": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
