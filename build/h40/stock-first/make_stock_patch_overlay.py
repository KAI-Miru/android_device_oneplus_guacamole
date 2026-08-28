#!/usr/bin/env python3
"""Create the narrowly scoped stock-side patch overlay for the hybrid ramdisk."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path, PurePosixPath

import newc


TARGET_PHYSICAL_PARTITIONS = {
    "system": ("/dev/block/bootdevice/by-name/system", "/system_root"),
    "vendor": ("/dev/block/bootdevice/by-name/vendor", "/vendor"),
    "odm": ("/dev/block/bootdevice/by-name/odm", "/odm"),
}

STOCK_LOGICAL_ROWS = {
    "system": "/system",
    "vendor": "/vendor",
    "product": "/product",
    "my_product": "/my_product",
    "my_engineering": "/my_engineering",
}

PRIVATE_CONTEXTS = (
    "/system/tw/linker64          u:object_r:system_linker_exec:s0",
    "/system/tw/bin(/.*)?         u:object_r:system_file:s0",
    "/system/tw/lib64(/.*)?       u:object_r:system_lib_file:s0",
)

CURATED_TWRP_FLAGS = """# Stock-first H.40 hybrid for guacamole's physical, slotted A/B layout.
/boot            emmc     /dev/block/bootdevice/by-name/boot       flags=slotselect
/system_root     ext4     /dev/block/bootdevice/by-name/system     flags=slotselect;backup=0;fsflags=ro
/system_image    emmc     /dev/block/bootdevice/by-name/system     flags=slotselect
/vendor          ext4     /dev/block/bootdevice/by-name/vendor     flags=slotselect;display="Vendor";backup=0;fsflags=ro
/vendor_image    emmc     /dev/block/bootdevice/by-name/vendor     flags=slotselect
/odm             ext4     /dev/block/bootdevice/by-name/odm        flags=slotselect;display="ODM";backup=0;fsflags=ro
/odm_image       emmc     /dev/block/bootdevice/by-name/odm        flags=slotselect
/metadata        ext4     /dev/block/bootdevice/by-name/metadata   flags=display="Metadata";backup=1
/data            ext4     /dev/block/bootdevice/by-name/userdata   flags=fileencryption=ice,keydirectory=/metadata/vold/metadata_encryption
/firmware        vfat     /dev/block/bootdevice/by-name/modem      flags=slotselect;display="Firmware";mounttodecrypt;fsflags=ro
/misc            emmc     /dev/block/bootdevice/by-name/misc
/modem           emmc     /dev/block/bootdevice/by-name/modem      flags=slotselect;backup=1;display="Modem"
/bluetooth       emmc     /dev/block/bootdevice/by-name/bluetooth  flags=slotselect;backup=1;subpartitionof=/modem
/dsp             emmc     /dev/block/bootdevice/by-name/dsp        flags=slotselect;backup=1;subpartitionof=/modem
/efs1            emmc     /dev/block/bootdevice/by-name/modemst1   flags=backup=1;display="EFS"
/efs2            emmc     /dev/block/bootdevice/by-name/modemst2   flags=backup=1;subpartitionof=/efs1
/efsc            emmc     /dev/block/bootdevice/by-name/fsc        flags=backup=1;subpartitionof=/efs1
/efsg            emmc     /dev/block/bootdevice/by-name/fsg        flags=backup=1;subpartitionof=/efs1
/op2             ext4     /dev/block/bootdevice/by-name/op2
/usbstorage      vfat     /dev/block/sdg1 /dev/block/sdg           flags=fsflags=utf8;display="USB Storage";storage;wipeingui;removable
"""


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_tree_file(root: Path, relative: str, archive_entry: newc.Entry) -> bytes:
    path = root / PurePosixPath(relative)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"cannot read stock tree path {path}: {exc}") from exc
    if data != archive_entry.data:
        raise SystemExit(
            f"stock tree/cpio mismatch for {relative}: tree={sha256(data)}, cpio={sha256(archive_entry.data)}"
        )
    return data


def decode_text(relative: str, blob: bytes) -> str:
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"expected UTF-8 text in {relative}") from exc


def patch_init(text: str) -> str:
    source = re.compile(r"^service recovery /system/bin/recovery\s*$", re.MULTILINE)
    if len(source.findall(text)) != 1:
        raise SystemExit("stock init.rc must contain exactly one unmodified recovery service")
    if "/system/tw/bin/recovery" in text:
        raise SystemExit("stock init.rc is already patched")
    text = source.sub("service recovery /system/tw/bin/recovery", text)

    fastbootd = re.compile(r"^service fastbootd /system/bin/fastbootd\s*$", re.MULTILINE)
    if len(fastbootd.findall(text)) != 1:
        raise SystemExit("stock init.rc must contain exactly one unmodified fastbootd service")
    return fastbootd.sub("service fastbootd /system/tw/bin/fastbootd", text)


def patch_linker_config(text: str) -> str:
    if "dir.twrp" in text or re.search(r"^\[twrp\]\s*$", text, re.MULTILINE):
        raise SystemExit("stock ld.config.txt already contains a TWRP namespace")
    recovery_dir = re.compile(r"^(dir\.recovery\s*=\s*/system/bin\s*)$", re.MULTILINE)
    if len(recovery_dir.findall(text)) != 1:
        raise SystemExit("unexpected stock ld.config.txt: missing unique dir.recovery mapping")
    text = recovery_dir.sub(r"\1\ndir.twrp = /system/tw/bin", text)
    if not text.endswith("\n"):
        text += "\n"
    text += (
        "\n[twrp]\n"
        "namespace.default.isolated = false\n"
        "namespace.default.search.paths = /system/tw/${LIB}\n"
    )
    return text


def physical_static_ab_fstab(text: str, relative: str) -> str:
    lines = text.splitlines(keepends=True)
    found: dict[str, list[int]] = {name: [] for name in STOCK_LOGICAL_ROWS}
    newline = "\r\n" if "\r\n" in text else "\n"
    for number, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 5:
            continue
        partition = fields[0]
        flags = fields[-1].split(",")
        if "logical" in flags and partition not in STOCK_LOGICAL_ROWS:
            raise SystemExit(f"unexpected logical row in {relative}: {stripped}")
        if partition not in STOCK_LOGICAL_ROWS:
            continue
        expected_mount = STOCK_LOGICAL_ROWS[partition]
        if fields[1] != expected_mount:
            raise SystemExit(
                f"unexpected {partition} mount point in {relative}: {fields[1]} (expected {expected_mount})"
            )
        if fields[2] not in ("ext4", "erofs"):
            raise SystemExit(f"unexpected {partition} filesystem in {relative}: {fields[2]}")
        if "logical" not in flags:
            raise SystemExit(f"{partition} is not marked logical in {relative}")
        found[partition].append(number)

    for partition, positions in found.items():
        if len(positions) != 1:
            raise SystemExit(f"missing logical {partition} row in {relative}")

    insert_at = min(position for positions in found.values() for position in positions)
    removed = {position for positions in found.values() for position in positions}
    physical_rows = []
    for _partition, (device, mount) in TARGET_PHYSICAL_PARTITIONS.items():
        physical_rows.extend(
            [
                f"{device:<52} {mount:<12} ext4   ro,barrier=1,discard   wait,slotselect{newline}",
                f"{device:<52} {mount:<12} erofs   ro                     wait,slotselect{newline}",
            ]
        )

    output = []
    for number, line in enumerate(lines):
        if number == insert_at:
            output.extend(physical_rows)
        if number not in removed:
            output.append(line)
    result = "".join(output)

    # Validate exactly two read-only, slotted alternatives per physical device.
    for partition, (device, mount) in TARGET_PHYSICAL_PARTITIONS.items():
        rows = []
        device_rows = []
        for line in result.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] == device:
                device_rows.append(fields)
                if fields[1] == mount:
                    rows.append(fields)
        if [row[2] for row in rows] != ["ext4", "erofs"]:
            raise SystemExit(f"failed to create ordered ext4/erofs alternatives for {partition} in {relative}")
        if any(row[1] != mount for row in device_rows):
            raise SystemExit(f"rewritten {partition} row has an unexpected mount point in {relative}")
        if any("logical" in row[-1].split(",") for row in rows):
            raise SystemExit(f"rewritten {partition} row is still logical in {relative}")
        if any("slotselect" not in row[-1].split(",") for row in rows):
            raise SystemExit(f"rewritten {partition} row lost slotselect flag in {relative}")
        if any(not row[3].startswith("ro") for row in rows):
            raise SystemExit(f"rewritten {partition} row is not read-only in {relative}")

    for line in result.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 5:
            continue
        if "logical" in fields[-1].split(","):
            raise SystemExit(f"logical recovery row remains in static-A/B fstab {relative}: {stripped}")
        if fields[0] in STOCK_LOGICAL_ROWS or fields[1] in {
            "/product",
            "/my_product",
            "/my_engineering",
        }:
            raise SystemExit(f"ColorOS logical/subimage row remains in {relative}: {stripped}")

    return result


def patch_contexts(text: str, relative: str) -> str:
    for rule in PRIVATE_CONTEXTS:
        expression = rule.split()[0]
        if expression in text:
            raise SystemExit(f"private context rule already exists in {relative}: {expression}")
    if not text.endswith("\n"):
        text += "\n"
    return text + "\n# Stock-first private TWRP runtime\n" + "\n".join(PRIVATE_CONTEXTS) + "\n"


def patch_adb_properties(text: str) -> str:
    replacements = {
        "ro.secure": "0",
        "ro.adb.secure": "0",
        "ro.debuggable": "1",
        "persist.sys.usb.config": "adb",
    }
    lines = text.splitlines(keepends=True)
    counts = {key: 0 for key in replacements}
    for number, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if "=" not in stripped or stripped.startswith("#"):
            continue
        key, _value = stripped.split("=", 1)
        if key not in replacements:
            continue
        ending = line[len(stripped) :]
        lines[number] = f"{key}={replacements[key]}{ending}"
        counts[key] += 1
    for key in ("ro.secure", "ro.adb.secure", "ro.debuggable", "persist.sys.usb.config"):
        if counts[key] < 1:
            raise SystemExit(f"missing expected property {key} in prop.default")
    return "".join(lines)


def patch_static_properties(text: str, enable_adb: bool) -> str:
    if re.search(r"^ro\.boot\.dynamic_partitions=", text, re.MULTILINE):
        raise SystemExit("stock static-A/B prop.default unexpectedly defines dynamic partitions")
    if re.search(r"^ro\.boot\.dynamic_partitions_retrofit=", text, re.MULTILINE):
        raise SystemExit("stock static-A/B prop.default unexpectedly defines retrofit dynamic partitions")

    result = text
    if enable_adb:
        result = patch_adb_properties(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-tree", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--enable-adb", action="store_true")
    args = parser.parse_args()

    archive_entries = newc.read(args.stock_cpio)
    archive = newc.index(archive_entries)
    required = {
        "system/etc/init/init.rc": patch_init,
        "system/etc/ld.config.txt": patch_linker_config,
        "etc/recovery.fstab": lambda text: physical_static_ab_fstab(text, "etc/recovery.fstab"),
        "system/etc/recovery.fstab": lambda text: physical_static_ab_fstab(
            text, "system/etc/recovery.fstab"
        ),
        "plat_file_contexts": lambda text: patch_contexts(text, "plat_file_contexts"),
        "system/etc/selinux/plat_file_contexts": lambda text: patch_contexts(
            text, "system/etc/selinux/plat_file_contexts"
        ),
    }
    if args.enable_adb:
        required["prop.default"] = lambda text: patch_static_properties(text, True)

    prop_entry = archive.get("prop.default")
    if prop_entry is None:
        raise SystemExit("missing required stock cpio entry: prop.default")
    prop_source = read_tree_file(args.stock_tree, "prop.default", prop_entry)
    if patch_static_properties(decode_text("prop.default", prop_source), False).encode("utf-8") != prop_source:
        raise SystemExit("static property validation unexpectedly changed prop.default")

    overlay = []
    records = []
    for relative, transform in required.items():
        entry = archive.get(relative)
        if entry is None:
            raise SystemExit(f"missing required stock cpio entry: {relative}")
        source = read_tree_file(args.stock_tree, relative, entry)
        target = transform(decode_text(relative, source)).encode("utf-8")
        if target == source:
            raise SystemExit(f"patch produced no change for {relative}")
        patched = replace(entry, data=target)
        overlay.append(patched)
        records.append(
            {
                "kind": "replacement",
                "target": relative,
                "source_sha256": sha256(source),
                "target_sha256": sha256(target),
                "source_bytes": len(source),
                "target_bytes": len(target),
            }
        )

    sepolicy = archive.get("sepolicy")
    if sepolicy is None:
        raise SystemExit("missing stock compiled sepolicy")
    for required_type in (b"system_linker_exec", b"system_file", b"system_lib_file", b"recovery"):
        if required_type not in sepolicy.data:
            raise SystemExit(f"stock compiled policy lacks required existing type {required_type.decode()}")

    next_ino = max(entry.ino for entry in archive_entries) + 1
    for target in ("etc/twrp.flags", "system/etc/twrp.flags"):
        if target in archive:
            raise SystemExit(f"stock archive unexpectedly already contains {target}")
        data = CURATED_TWRP_FLAGS.encode("utf-8")
        overlay.append(newc.regular_file(target, data, mode=0o100644, ino=next_ino))
        next_ino += 1
        records.append(
            {
                "kind": "addition",
                "target": target,
                "target_sha256": sha256(data),
                "target_bytes": len(data),
            }
        )

    newc.write(args.output, overlay)
    roundtrip = newc.index(newc.read(args.output))
    if set(roundtrip) != {entry.name for entry in overlay}:
        raise SystemExit("stock patch overlay path set changed on round-trip")
    for entry in overlay:
        if roundtrip[entry.name] != entry:
            raise SystemExit(f"stock patch overlay round-trip mismatch for {entry.name}")

    manifest = {
        "format": 1,
        "partition_layout": "physical_static_ab",
        "stock_cpio_sha256": sha256(args.stock_cpio.read_bytes()),
        "enable_adb": args.enable_adb,
        "overlay_entry_count": len(overlay),
        "overlay_bytes": args.output.stat().st_size,
        "overlay_sha256": sha256(args.output.read_bytes()),
        "records": records,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "entries": len(overlay),
                "enable_adb": args.enable_adb,
                "bytes": args.output.stat().st_size,
                "sha256": manifest["overlay_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
