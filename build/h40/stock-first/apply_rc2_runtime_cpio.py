#!/usr/bin/env python3
"""Install the compiled RC2 recovery, helper, Keystore2 closure, and resources."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import newc
from make_private_twrp_overlay import (
    PRIVATE_INTERPRETER,
    patch_exact_cstring,
    patch_pt_interp,
)


RAW_INTERPRETER = "/system/bin/linker64"
RAW_SELF_PATH = "/system/bin/recovery"
PRIVATE_SELF_PATH = "/system/tw/bin/r"
PRIVATE_RECOVERY = "system/tw/bin/recovery"
STOCK_RECOVERY = "system/bin/recovery"
RECOVERY_ALIAS = "system/tw/bin/r"
HELPER = "system/bin/oplus_h40_credential_helper"
SERVICE_CONTEXTS = "system/etc/selinux/plat_service_contexts"
KEY_CONTEXTS = "system/etc/selinux/plat_keystore2_key_contexts"
PRIVATE_VERIFY = (
    b"_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi"
)
RECOVERY_MARKERS = (
    b"[OPLUS DECRYPT] system identity: using mounted dynamic system",
    b"[OPLUS DECRYPT] credential handoff: launching exact-H.40 isolated credential gate for user 0",
    b"[OPLUS DECRYPT] parent key install: deriving and installing the accepted user 0 credential",
    b"[OPLUS DECRYPT] CE layout:",
    b"direct-aes-minimal",
    b"direct-aes-legacy-none",
    b"encrypt,verity,quota,project",
    b"I:[TWRP FORMAT] enforcing Android ext4 userdata features: %s",
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


def verify_sha256sums(root: Path) -> int:
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        raise SystemExit(f"runtime checksum manifest is absent: {manifest}")
    checked = 0
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        expected, relative = raw_line.split(None, 1)
        relative = relative.strip()
        while relative.startswith("./"):
            relative = relative[2:]
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"runtime checksum input is missing: {relative}")
        actual = sha256(path.read_bytes())
        if actual != expected.lower():
            raise SystemExit(
                f"runtime checksum mismatch for {relative}: expected={expected} actual={actual}"
            )
        checked += 1
    return checked


def merge_exact_before_wildcard(original: bytes, fragment: bytes) -> bytes:
    rows = [line.split() for line in fragment.splitlines() if line.strip()]
    if not rows or any(len(row) != 2 for row in rows):
        raise SystemExit("service-context fragment is malformed")
    names = {row[0] for row in rows}
    if len(names) != len(rows):
        raise SystemExit("service-context fragment contains duplicate names")
    retained = [
        line
        for line in original.splitlines(keepends=True)
        if not line.split() or line.split()[0] not in names
    ]
    wildcards = [
        index
        for index, line in enumerate(retained)
        if line.split() and line.split()[0] == b"*"
    ]
    if wildcards != [len(retained) - 1]:
        raise SystemExit("service-context wildcard is not the single final line")
    canonical = fragment if fragment.endswith(b"\n") else fragment + b"\n"
    return b"".join(retained[:-1]) + canonical + retained[-1]


def merge_exact_namespaces(original: bytes, fragment: bytes) -> bytes:
    rows = [line.split() for line in fragment.splitlines() if line.strip()]
    if not rows or any(len(row) != 2 for row in rows):
        raise SystemExit("Keystore namespace fragment is malformed")
    names = {row[0] for row in rows}
    if len(names) != len(rows):
        raise SystemExit("Keystore namespace fragment contains duplicate names")
    retained = [
        line
        for line in original.splitlines(keepends=True)
        if not line.split() or line.split()[0] not in names
    ]
    prefix = b"".join(retained)
    if prefix and not prefix.endswith(b"\n"):
        prefix += b"\n"
    canonical = fragment if fragment.endswith(b"\n") else fragment + b"\n"
    return prefix + canonical


def expected_mode(path: str) -> int:
    if (
        path == "system/tw/linker64"
        or path.startswith("system/tw/bin/")
        or path == HELPER
    ):
        return 0o100755
    return 0o100644


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--recovery-root", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    install_root = args.runtime / "install-root"
    context_root = args.runtime / "context-shim"
    runtime_checks = verify_sha256sums(args.runtime)

    raw_recovery = (args.recovery_root / "system/bin/recovery").read_bytes()
    helper = (args.recovery_root / "system/bin/oplus_h40_credential_helper").read_bytes()
    compiled_keystore2 = (args.recovery_root / "system/bin/keystore2").read_bytes()
    packaged_keystore2 = (install_root / "system/tw/bin/keystore2").read_bytes()
    relocated_keystore2, keystore_old_interpreter = patch_pt_interp(
        compiled_keystore2, PRIVATE_INTERPRETER, expected_old=RAW_INTERPRETER
    )
    if relocated_keystore2 != packaged_keystore2:
        raise SystemExit("packaged Keystore2 differs from the compiled private relocation")
    if b"H40_RECOVERY_KEYSTORE2_PERMISSION_SHIM_V51" not in packaged_keystore2:
        raise SystemExit("Keystore2 permission-shim marker is absent")
    for marker in RECOVERY_MARKERS:
        if marker not in raw_recovery:
            raise SystemExit(f"compiled recovery is missing marker: {marker!r}")
    if PRIVATE_VERIFY in raw_recovery or PRIVATE_VERIFY not in helper:
        raise SystemExit("OEM verifier isolation between recovery and helper failed")

    relocated, recovery_old_interpreter = patch_pt_interp(
        raw_recovery, PRIVATE_INTERPRETER, expected_old=RAW_INTERPRETER
    )
    relocated, self_path_count = patch_exact_cstring(
        relocated, RAW_SELF_PATH, PRIVATE_SELF_PATH
    )
    if self_path_count != 1 or len(relocated) != len(raw_recovery):
        raise SystemExit("private recovery fixed-size relocation failed")

    source_entries = newc.read(args.input)
    source_index = newc.index(source_entries)
    if len(source_entries) != len(source_index):
        raise SystemExit("source ramdisk contains duplicate paths")
    for required in (
        PRIVATE_RECOVERY,
        STOCK_RECOVERY,
        RECOVERY_ALIAS,
        SERVICE_CONTEXTS,
        "system/etc/init/init.rc",
        "etc/recovery.fstab",
        "system/etc/recovery.fstab",
        "etc/twrp.flags",
        "system/etc/twrp.flags",
    ):
        if required not in source_index:
            raise SystemExit(f"source ramdisk is missing required path: {required}")
    alias = source_index[RECOVERY_ALIAS]
    if alias.mode & 0o170000 != 0o120000 or alias.data != b"recovery":
        raise SystemExit("private recovery alias is malformed")
    replacements: dict[str, bytes] = {
        PRIVATE_RECOVERY: relocated,
        HELPER: helper,
    }
    for path in sorted(install_root.rglob("*")):
        if path.is_file():
            replacements[path.relative_to(install_root).as_posix()] = path.read_bytes()
    service_fragment = (context_root / "plat_service_contexts.merge").read_bytes()
    replacements[SERVICE_CONTEXTS] = merge_exact_before_wildcard(
        source_index[SERVICE_CONTEXTS].data, service_fragment
    )
    key_fragment = (context_root / "plat_keystore2_key_contexts.merge").read_bytes()
    key_original = source_index[KEY_CONTEXTS].data if KEY_CONTEXTS in source_index else b""
    replacements[KEY_CONTEXTS] = merge_exact_namespaces(key_original, key_fragment)

    twres_root = args.recovery_root / "twres"
    if not twres_root.is_dir():
        raise SystemExit("compiled recovery root has no TWRP resources")
    twres_count = 0
    for path in sorted(twres_root.rglob("*")):
        if path.is_file():
            replacements["twres/" + path.relative_to(twres_root).as_posix()] = path.read_bytes()
            twres_count += 1
    if twres_count < 20:
        raise SystemExit(f"unexpectedly small TWRP resource set: {twres_count}")

    remaining = dict(replacements)
    output_entries = []
    changed = {}
    for entry in source_entries:
        data = remaining.pop(entry.name, None)
        if data is None:
            output_entries.append(entry)
            continue
        output_entries.append(replace(entry, data=data))
        if data != entry.data:
            changed[entry.name] = {
                "before_sha256": sha256(entry.data),
                "after_sha256": sha256(data),
            }

    next_ino = max(entry.ino for entry in source_entries) + 1
    added = {}
    for target, data in sorted(remaining.items()):
        mode = expected_mode(target)
        output_entries.append(newc.regular_file(target, data, mode=mode, ino=next_ino))
        added[target] = {"bytes": len(data), "sha256": sha256(data), "mode": oct(mode)}
        next_ino += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    newc.write(args.output, output_entries)
    final_entries = newc.read(args.output)
    final_index = newc.index(final_entries)
    if len(final_entries) != len(final_index):
        raise SystemExit("runtime ramdisk contains duplicate paths")
    changed_paths = set(changed)
    for before in source_entries:
        after = final_index.get(before.name)
        if after is None:
            raise SystemExit(f"source entry disappeared: {before.name}")
        if before.name in changed_paths:
            if metadata(before) != metadata(after):
                raise SystemExit(f"metadata changed for replacement: {before.name}")
        elif before != after:
            raise SystemExit(f"unapproved source entry changed: {before.name}")
    if final_index[STOCK_RECOVERY] != source_index[STOCK_RECOVERY]:
        raise SystemExit("stock ColorOS recovery changed")
    if final_index[PRIVATE_RECOVERY].data != relocated:
        raise SystemExit("private recovery replacement mismatch")
    if final_index[HELPER].data != helper:
        raise SystemExit("isolated helper replacement mismatch")
    for target, data in replacements.items():
        if final_index[target].data != data:
            raise SystemExit(f"runtime payload mismatch: {target}")

    report = {
        "format": 1,
        "name": "guacamole-h40-rc2-private-runtime-cpio",
        "source_entries": len(source_entries),
        "final_entries": len(final_entries),
        "source_sha256": sha256(args.input.read_bytes()),
        "output_sha256": sha256(args.output.read_bytes()),
        "compiled_recovery_sha256": sha256(raw_recovery),
        "isolated_helper_sha256": sha256(helper),
        "recovery_source_interpreter": recovery_old_interpreter,
        "recovery_private_interpreter": PRIVATE_INTERPRETER,
        "keystore2_source_interpreter": keystore_old_interpreter,
        "runtime_files_verified": runtime_checks,
        "twres_files_installed": twres_count,
        "changed": changed,
        "added": added,
        "checks": {
            "unrelated_entries_preserved": True,
            "replacement_metadata_preserved": True,
            "stock_recovery_preserved": True,
            "private_recovery_exact_compiled": True,
            "owner_only_adapter_markers_present": True,
            "oem_verifier_isolated": True,
            "keystore2_closure_installed": True,
            "twrp_resources_installed": True,
            "no_duplicate_paths": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
