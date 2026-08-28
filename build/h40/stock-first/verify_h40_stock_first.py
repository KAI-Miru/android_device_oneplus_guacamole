#!/usr/bin/env python3
"""Independently verify the complete Guacamole H.40 stock-first boot image."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
from pathlib import Path

import newc
from make_private_twrp_overlay import PRIVATE_INTERPRETER, patch_exact_cstring, patch_pt_interp
from make_stock_patch_overlay import LEGACY_INSTALLER_SHELL, LEGACY_INSTALLER_SHELL_TARGET
from repack_boot_v2 import AVB_FOOTER_MAGIC, parse_boot_v2


EXPECTED_SIZE = 100663296
PRIVATE_VERIFY = (
    b"_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi"
)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def metadata(entry: newc.Entry) -> tuple[int, ...]:
    return (
        entry.ino,
        entry.mode,
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.mtime,
        entry.devmajor,
        entry.devminor,
        entry.rdevmajor,
        entry.rdevminor,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def verify_record(path: Path, record: dict, label: str) -> bytes:
    data = path.read_bytes()
    require(len(data) == record["bytes"], f"{label} size mismatch")
    require(sha256(data) == record["sha256"], f"{label} hash mismatch")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-boot", type=Path, required=True)
    parser.add_argument("--final-boot", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--raw-cpio", type=Path, required=True)
    parser.add_argument("--gzip-cpio", type=Path, required=True)
    parser.add_argument("--prebuilt-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--recovery-root", type=Path, required=True)
    parser.add_argument("--stock-patch-report", type=Path, required=True)
    parser.add_argument("--fix-report", type=Path, required=True)
    parser.add_argument("--runtime-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    for name, record in manifest["files"].items():
        verify_record(args.prebuilt_dir / name, record, name)
    for name, record in manifest["overlay"].items():
        verify_record(args.prebuilt_dir / "overlay" / name, record, name)
    repo_root = args.prebuilt_dir.parents[1]
    for name, record in manifest["configuration"].items():
        verify_record(repo_root / name, record, name)

    stock = parse_boot_v2(args.stock_boot)
    final = parse_boot_v2(args.final_boot)
    require(len(final.image) == EXPECTED_SIZE, "final boot image is not exactly 96 MiB")
    require(len(final.image) == manifest["partition"]["bytes"], "partition manifest size mismatch")
    for component in ("kernel", "second", "recovery_dtbo", "dtb"):
        require(getattr(final, component) == getattr(stock, component), f"stock {component} changed")
    require(final.ramdisk == args.gzip_cpio.read_bytes(), "final ramdisk differs from generated gzip")
    require(gzip.decompress(final.ramdisk) == args.raw_cpio.read_bytes(), "gzip round trip mismatch")
    require(
        len(final.ramdisk) <= manifest["partition"]["max_final_ramdisk_gzip_bytes"],
        "final ramdisk exceeds the pinned boot-partition safety limit",
    )

    require(final.image[-64:-60] == AVB_FOOTER_MAGIC, "AVB footer is absent")
    magic, major, minor, original_size, vbmeta_offset, vbmeta_size, reserved = struct.unpack(
        ">4sIIQQQ28s", final.image[-64:]
    )
    require(magic == AVB_FOOTER_MAGIC and (major, minor) == (1, 0), "AVB footer version is invalid")
    require(original_size == final.original_image_size == vbmeta_offset, "AVB payload bounds are invalid")
    require(vbmeta_offset + vbmeta_size <= len(final.image) - 64, "AVB vbmeta extends past footer")
    require(not any(reserved), "AVB footer reserved bytes are nonzero")

    stock_entries = newc.read(args.stock_cpio)
    final_entries = newc.read(args.raw_cpio)
    stock_index = newc.index(stock_entries)
    final_index = newc.index(final_entries)
    require(len(stock_entries) == len(stock_index), "stock CPIO contains duplicate paths")
    require(len(final_entries) == len(final_index), "final CPIO contains duplicate paths")

    stock_patch = json.loads(args.stock_patch_report.read_text(encoding="utf-8"))
    fix_report = json.loads(args.fix_report.read_text(encoding="utf-8"))
    runtime_report = json.loads(args.runtime_report.read_text(encoding="utf-8"))
    allowed_changes = {
        record["target"]
        for record in stock_patch["records"]
        if record["kind"] == "replacement"
    }
    allowed_changes.update(fix_report["changed"])
    allowed_changes.update(runtime_report["changed"])
    actual_changes = set()
    for name, before in stock_index.items():
        after = final_index.get(name)
        require(after is not None, f"stock entry disappeared: {name}")
        require(metadata(before) == metadata(after), f"stock metadata changed: {name}")
        if before.data != after.data:
            actual_changes.add(name)
    require(actual_changes <= allowed_changes, f"unapproved stock changes: {sorted(actual_changes - allowed_changes)}")
    require(final_index["system/bin/recovery"] == stock_index["system/bin/recovery"], "stock recovery changed")
    require(final_index["sepolicy"] == stock_index["sepolicy"], "stock SELinux policy changed")

    sbin = final_index.get("sbin")
    require(
        sbin is not None and sbin.mode & 0o170000 == 0o040000,
        "legacy ZIP installer parent is not a directory",
    )
    installer_shell = final_index.get(LEGACY_INSTALLER_SHELL)
    require(installer_shell is not None, "legacy ZIP installer shell route is absent")
    require(
        installer_shell.mode & 0o170000 == 0o120000,
        "legacy ZIP installer shell route is not a symlink",
    )
    require(
        installer_shell.data == LEGACY_INSTALLER_SHELL_TARGET,
        "legacy ZIP installer shell route has the wrong target",
    )
    system_shell = final_index.get(LEGACY_INSTALLER_SHELL_TARGET.lstrip(b"/").decode("ascii"))
    require(system_shell is not None, "legacy ZIP installer shell target is absent")
    require(
        system_shell.mode & 0o170000 == 0o100000 and system_shell.mode & 0o111 != 0,
        "legacy ZIP installer shell target is not a regular executable",
    )
    installer_shell_records = [
        record
        for record in stock_patch["records"]
        if record.get("target") == LEGACY_INSTALLER_SHELL
    ]
    require(
        len(installer_shell_records) == 1
        and installer_shell_records[0].get("entry_type") == "symlink"
        and installer_shell_records[0].get("symlink_target")
        == LEGACY_INSTALLER_SHELL_TARGET.decode("ascii")
        and installer_shell_records[0].get("purpose") == "legacy_recovery_zip_installer"
        and installer_shell_records[0].get("target_bytes") == len(installer_shell.data)
        and installer_shell_records[0].get("target_sha256") == sha256(installer_shell.data),
        "legacy ZIP installer shell route is not audited in the stock overlay manifest",
    )

    raw_recovery = (args.recovery_root / "system/bin/recovery").read_bytes()
    relocated, _ = patch_pt_interp(raw_recovery, PRIVATE_INTERPRETER, expected_old="/system/bin/linker64")
    relocated, replacements = patch_exact_cstring(relocated, "/system/bin/recovery", "/system/tw/bin/r")
    require(replacements == 1, "private recovery self-path relocation count changed")
    require(final_index["system/tw/bin/recovery"].data == relocated, "private recovery differs from compiled output")
    helper = (args.recovery_root / "system/bin/oplus_h40_credential_helper").read_bytes()
    require(final_index["system/bin/oplus_h40_credential_helper"].data == helper, "credential helper mismatch")
    require(PRIVATE_VERIFY not in relocated and PRIVATE_VERIFY in helper, "OEM verifier isolation failed")
    for marker in (
        b"[OPLUS V56 LAYOUT]",
        b"direct-aes-minimal",
        b"direct-aes-legacy-none",
        b"[H40 PORTIDENTITY] using mounted dynamic system",
        b"[H40 V51 PARENT]",
    ):
        require(marker in relocated, f"private recovery lacks marker {marker!r}")

    fstab = final_index["etc/recovery.fstab"].data
    flags = final_index["etc/twrp.flags"].data
    require(fstab == final_index["system/etc/recovery.fstab"].data, "recovery fstab mirrors differ")
    require(flags == final_index["system/etc/twrp.flags"].data, "TWRP flag mirrors differ")
    for forbidden in (b"special_preload", b"opporeserve", b"/usb_otg", b"/external_sd"):
        require(forbidden not in fstab and forbidden not in flags, f"phantom mount survived: {forbidden!r}")
    require(fstab.count(b"/dev/block/bootdevice/by-name/system") == 1, "System fstab row is duplicated")
    require(b"/dev/block/bootdevice/by-name/op2       /cache" in fstab, "op2 cache mapping is absent")

    init_rc = final_index["system/etc/init/init.rc"].data
    qcom_rc = final_index["init.recovery.qcom.rc"].data
    require(b"mtk-msdc.0" not in init_rc, "MediaTek e2fsck path survived")
    require(b"wait /dev/block/bootdevice/by-name/modem" not in init_rc, "obsolete modem wait survived")
    require(init_rc.count(b"mkdir /config/usb_gadget/g1/functions/mtp.gs0") == 3, "MTP configfs setup is incomplete")
    require(init_rc.count(b"property:sys.usb.config=sideload") == 2, "sideload ownership rules changed")
    require(b"sys.usb.ffs.ready" not in qcom_rc, "Qualcomm init still competes for USB ownership")
    require(b"service qseecomd /system/bin/qseecomd\n    disabled" in init_rc, "qseecomd is not explicit-start-only")
    require(b"service keystore2 /system/tw/bin/keystore2" in final_index["system/etc/init/keystore2.rc"].data, "private Keystore2 service is absent")
    require(b"    disabled" in final_index["system/etc/init/keystore2.rc"].data, "private Keystore2 is not explicit-start-only")

    for target, record in manifest["overlay"].items():
        require(target in final_index, f"explicit overlay is absent: {target}")
        require(len(final_index[target].data) == record["bytes"], f"overlay size mismatch: {target}")
        require(sha256(final_index[target].data) == record["sha256"], f"overlay hash mismatch: {target}")
    require("init.recovery.usb.rc" not in final_index, "obsolete second USB owner survived")

    report = {
        "format": 1,
        "name": "guacamole-h40-stock-first-full-boot-verification",
        "image": {
            "bytes": len(final.image),
            "sha256": sha256(final.image),
            "ramdisk_sha256": sha256(final.ramdisk),
        },
        "ramdisk": {
            "stock_entries": len(stock_entries),
            "final_entries": len(final_entries),
            "approved_stock_changes": sorted(actual_changes),
        },
        "checks": {
            "all_prebuilt_hashes_exact": True,
            "stock_boot_components_exact": True,
            "stock_recovery_exact": True,
            "stock_policy_exact": True,
            "private_recovery_exact_compiled": True,
            "legacy_zip_installer_shell_route_present": True,
            "universal_owner_decryption_markers_present": True,
            "oem_verifier_isolated": True,
            "mount_table_rc2_exact": True,
            "phantom_mounts_absent": True,
            "single_system_entry": True,
            "op2_is_cache": True,
            "single_usb_owner": True,
            "mtp_and_sideload_rules_present": True,
            "qsee_and_keystore_explicit_start_only": True,
            "commondcs_system_ext_rc2_exact": True,
            "haptics_tzdata_qsee_plugins_exact": True,
            "unrelated_stock_entries_preserved": True,
            "no_duplicate_cpio_paths": True,
            "gzip_roundtrip_exact": True,
            "ramdisk_within_partition_safety_limit": True,
            "avb_footer_structurally_valid": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
