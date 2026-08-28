#!/usr/bin/env python3
"""Apply the log-derived H.40 recovery fixes to an unpacked hybrid ramdisk.

The stock-first image deliberately preserves ColorOS init and service files.
This transformer therefore makes only exact, fail-closed edits and copies the
small device payloads that the hybrid assembly previously omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEVICE_ROOT = REPO_ROOT / "recovery" / "root"

MTK_E2FSCK = (
    "    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/cache\n"
    "    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/userdata\n"
)
MODEM_WAIT = "    wait /dev/block/bootdevice/by-name/modem\n"
EARLY_HEALTHD_START = "    start healthd\n"
LEGACY_CPUACCT_MOUNT = "    mount cgroup none /acct cpuacct\n"
SYSTEM_BACKGROUND_WRITEPID = "    writepid /dev/cpuset/system-background/tasks\n"
DUPLICATE_CONFIGFS_MOUNT = (
    "on fs && property:sys.usb.configfs=1\n"
    "    mount configfs none /config\n"
)
PERSIST_FSTAB = (
    "/dev/block/bootdevice/by-name/persist      /persist        ext4    "
    "defaults                                                        defaults\n"
)
OP2_FLAG_PREFIX = "/op2"

QSEECOMD_SERVICE = """service qseecomd /system/bin/qseecomd
    disabled
    seclabel u:r:recovery:s0
"""

GATEKEEPERD_SERVICE = """service gatekeeperd /system/bin/gatekeeperd /data/misc/gatekeeper
    seclabel u:r:recovery:s0
"""
GATEKEEPERD_SERVICE_DISABLED = """service gatekeeperd /system/bin/gatekeeperd /data/misc/gatekeeper
    disabled
    seclabel u:r:recovery:s0
"""

VNDSERVICEMANAGER_SERVICE = """service vndservicemanager /vendor/bin/vndservicemanager /dev/vndbinder
    seclabel u:r:recovery:s0
"""
VNDSERVICEMANAGER_SERVICE_DISABLED = """service vndservicemanager /vendor/bin/vndservicemanager /dev/vndbinder
    disabled
    seclabel u:r:recovery:s0
"""

IRSC_UTIL_SERVICE = """service irsc_util /system/bin/irsc_util "/vendor/etc/sec_config"
    user root
    oneshot
    seclabel u:r:recovery:s0
"""
IRSC_UTIL_SERVICE_DISABLED = """service irsc_util /system/bin/irsc_util "/vendor/etc/sec_config"
    disabled
    user root
    oneshot
    seclabel u:r:recovery:s0
"""

WPA_SUPPLICANT_SERVICE = (
    "service wpa_supplicant /system/bin/wpa_supplicant \\\n"
    "    -Dnl80211 -iwlan0 -dd -O/data/misc/wifi/sockets \\\n"
    "    -c/data/misc/wifi/wpa_supplicant.conf\n"
    "    seclabel u:r:recovery:s0\n"
)
WPA_SUPPLICANT_SERVICE_DISABLED = (
    "service wpa_supplicant /system/bin/wpa_supplicant \\\n"
    "    -Dnl80211 -iwlan0 -dd -O/data/misc/wifi/sockets \\\n"
    "    -c/data/misc/wifi/wpa_supplicant.conf\n"
    "    disabled\n"
    "    seclabel u:r:recovery:s0\n"
)

DUPLICATE_USB_OWNER = """on property:sys.usb.ffs.ready=1
    mkdir /config/usb_gadget/g1/configs/b.1 0777 shell shell
    symlink /config/usb_gadget/g1/configs/b.1 /config/usb_gadget/g1/os_desc/b.1
    mkdir /config/usb_gadget/g1/configs/b.1/strings/0x409 0770 shell shell
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "adb"
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
"""

MTP_FUNCTION_ANCHOR = "    mkdir /config/usb_gadget/g1/functions/ffs.adb\n"
MTP_FUNCTION = "    mkdir /config/usb_gadget/g1/functions/mtp.gs0\n"
NONE_LINK_ANCHOR = "    rm /config/usb_gadget/g1/configs/b.1/f1\n"
NONE_SECOND_LINK = "    rm /config/usb_gadget/g1/configs/b.1/f2\n"

MTP_RULES_ANCHOR = """on property:sys.usb.config=fastboot && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/idProduct 0x4EE0
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "fastboot"
    symlink /config/usb_gadget/g1/functions/ffs.fastboot /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}
"""

MTP_RULES = """

# TWRP MTP uses the legacy configfs mtp function exposed as /dev/mtp_usb.
on property:sys.usb.config=mtp && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    write /config/usb_gadget/g1/idVendor 0x2A70
    write /config/usb_gadget/g1/idProduct 0xF003
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "mtp"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    symlink /config/usb_gadget/g1/functions/mtp.gs0 /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=mtp,adb && property:sys.usb.configfs=1
    start adbd

on property:sys.usb.config=mtp,adb && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    write /config/usb_gadget/g1/idVendor 0x2A70
    write /config/usb_gadget/g1/idProduct 0x9012
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "mtp_adb"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    symlink /config/usb_gadget/g1/functions/mtp.gs0 /config/usb_gadget/g1/configs/b.1/f1
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}
"""

PAYLOADS = (
    "system/usr/share/zoneinfo/tzdata",
    "vendor/firmware/aw8697_rtp.bin",
    "vendor/firmware/aw8697_haptic_170.bin",
    "vendor/firmware/40ms_RTP_170Hz.bin",
    "vendor/lib64/libspl.so",
    "vendor/lib64/libops.so",
    "etc/cgroups.json",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text_lf(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def drop_exact_lines(text: str, line: str, expected: int, label: str) -> str:
    lines = text.splitlines(keepends=True)
    count = sum(candidate == line for candidate in lines)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} exact anchors, found {count}")
    return "".join(candidate for candidate in lines if candidate != line)


def drop_op2_flag(path: Path) -> bool:
    if not path.exists():
        return False
    lines = read_text(path).splitlines(keepends=True)
    matches = [line for line in lines if line.lstrip().startswith(OP2_FLAG_PREFIX)]
    if len(matches) > 1:
        raise SystemExit(f"{path}: duplicate /op2 flags")
    if not matches:
        return False
    write_text_lf(path, "".join(line for line in lines if line not in matches))
    return True


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ramdisk_root", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = args.ramdisk_root.resolve()
    if not root.is_dir():
        raise SystemExit(f"ramdisk root is not a directory: {root}")

    init_path = root / "system/etc/init/init.rc"
    qcom_path = root / "init.recovery.qcom.rc"
    fstab_path = root / "etc/recovery.fstab"
    for required in (init_path, qcom_path, fstab_path):
        if not required.is_file():
            raise SystemExit(f"hybrid ramdisk is missing {required.relative_to(root)}")

    init_rc = read_text(init_path)
    init_rc = replace_once(init_rc, MTK_E2FSCK, "", "MediaTek e2fsck cleanup")
    init_rc = replace_once(init_rc, MODEM_WAIT, "", "obsolete modem wait")
    init_rc = replace_once(
        init_rc, EARLY_HEALTHD_START, "", "premature health service start"
    )
    init_rc = replace_once(
        init_rc, LEGACY_CPUACCT_MOUNT, "", "duplicate cpuacct mount"
    )
    init_rc = drop_exact_lines(
        init_rc,
        SYSTEM_BACKGROUND_WRITEPID,
        3,
        "missing recovery cpuset writes",
    )
    init_rc = replace_once(
        init_rc,
        GATEKEEPERD_SERVICE,
        GATEKEEPERD_SERVICE_DISABLED,
        "gatekeeper explicit-start service",
    )
    init_rc = replace_once(
        init_rc,
        VNDSERVICEMANAGER_SERVICE,
        VNDSERVICEMANAGER_SERVICE_DISABLED,
        "unused vendor service manager",
    )
    init_rc = replace_once(
        init_rc,
        IRSC_UTIL_SERVICE,
        IRSC_UTIL_SERVICE_DISABLED,
        "unused IRSC utility",
    )
    init_rc = replace_once(
        init_rc,
        WPA_SUPPLICANT_SERVICE,
        WPA_SUPPLICANT_SERVICE_DISABLED,
        "unused recovery Wi-Fi service",
    )
    init_rc = replace_once(
        init_rc,
        DUPLICATE_CONFIGFS_MOUNT,
        "on fs && property:sys.usb.configfs=1\n",
        "duplicate configfs mount",
    )
    # Stock init contains three independent configfs construction sections.
    if init_rc.count(MTP_FUNCTION_ANCHOR) != 3:
        raise SystemExit("stock init: expected three ffs.adb construction anchors")
    init_rc = init_rc.replace(MTP_FUNCTION_ANCHOR, MTP_FUNCTION_ANCHOR + MTP_FUNCTION)
    none_at = init_rc.find("on property:sys.usb.config=none && property:sys.usb.configfs=1")
    fastboot_at = init_rc.find("on property:sys.usb.config=fastboot && property:sys.usb.configfs=0")
    if none_at < 0 or fastboot_at < 0 or fastboot_at >= none_at:
        raise SystemExit("stock init: USB none trigger boundaries are unexpected")
    tail = init_rc[none_at:]
    tail = replace_once(tail, NONE_LINK_ANCHOR, NONE_LINK_ANCHOR + NONE_SECOND_LINK,
                        "USB link cleanup")
    init_rc = init_rc[:none_at] + tail
    init_rc = replace_once(init_rc, MTP_RULES_ANCHOR, MTP_RULES_ANCHOR + MTP_RULES,
                           "MTP rule insertion")
    write_text_lf(init_path, init_rc)

    qcom_rc = replace_once(read_text(qcom_path), DUPLICATE_USB_OWNER, "",
                           "duplicate Qualcomm USB owner")
    write_text_lf(qcom_path, qcom_rc)

    fstab = replace_once(read_text(fstab_path), PERSIST_FSTAB, "",
                         "duplicate persist entry")
    write_text_lf(fstab_path, fstab)
    changed_flags = [
        path.relative_to(root).as_posix()
        for path in (root / "etc/twrp.flags", root / "system/etc/twrp.flags")
        if drop_op2_flag(path)
    ]
    if not changed_flags:
        raise SystemExit("hybrid ramdisk contains no /op2 TWRP flag to remove")

    copied = {}
    for relative in PAYLOADS:
        source = DEVICE_ROOT / relative
        target = root / relative
        if not source.is_file() or source.stat().st_size == 0:
            raise SystemExit(f"device payload is missing or empty: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied[relative] = {"bytes": target.stat().st_size, "sha256": sha256(target)}

    checks = {
        "duplicate_usb_owner_removed": DUPLICATE_USB_OWNER not in read_text(qcom_path),
        "mtp_function_and_rules_present": (
            read_text(init_path).count(MTP_FUNCTION) == 3
            and MTP_RULES.strip() in read_text(init_path)
        ),
        "obsolete_modem_wait_removed": MODEM_WAIT not in read_text(init_path),
        "premature_healthd_start_removed": (
            EARLY_HEALTHD_START not in read_text(init_path)
        ),
        "duplicate_cpuacct_mount_removed": (
            LEGACY_CPUACCT_MOUNT not in read_text(init_path)
        ),
        "missing_cpuset_writes_removed": (
            all(
                line != SYSTEM_BACKGROUND_WRITEPID
                for line in read_text(init_path).splitlines(keepends=True)
            )
        ),
        "unused_stock_services_disabled": all(
            service in read_text(init_path)
            for service in (
                GATEKEEPERD_SERVICE_DISABLED,
                VNDSERVICEMANAGER_SERVICE_DISABLED,
                IRSC_UTIL_SERVICE_DISABLED,
                WPA_SUPPLICANT_SERVICE_DISABLED,
            )
        ),
        "qseecomd_remains_explicit_start_only": (
            QSEECOMD_SERVICE in read_text(init_path)
        ),
        "duplicate_configfs_mount_removed": (
            DUPLICATE_CONFIGFS_MOUNT not in read_text(init_path)
        ),
        "mediatek_e2fsck_removed": MTK_E2FSCK not in read_text(init_path),
        "persist_duplicate_removed": PERSIST_FSTAB not in read_text(fstab_path),
        "op2_duplicate_removed": all(
            not any(
                line.lstrip().startswith(OP2_FLAG_PREFIX)
                for line in read_text(path).splitlines()
            )
            for path in (root / "etc/twrp.flags", root / "system/etc/twrp.flags")
            if path.exists()
        ),
    }
    if not all(checks.values()):
        raise SystemExit(f"post-apply validation failed: {checks}")

    report = {
        "format": 1,
        "name": "guacamole-h40-rc-recovery-fixes",
        "ramdisk_root": str(root),
        "patched_files": [
            "system/etc/init/init.rc",
            "init.recovery.qcom.rc",
            "etc/recovery.fstab",
            *changed_flags,
        ],
        "copied_payloads": copied,
        "checks": checks,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        write_text_lf(args.report, rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
