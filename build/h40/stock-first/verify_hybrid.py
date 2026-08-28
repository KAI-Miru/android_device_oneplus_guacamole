#!/usr/bin/env python3
"""Strict structural, ABI, routing, and reproducibility checks for a hybrid ramdisk."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
from collections import defaultdict, deque
from dataclasses import replace
from pathlib import Path

import newc
import h40_dlopen
import h40_cryptoeng_dependency as h40_cryptoeng


MANDATORY_HELPERS = (
    "minadbd",
    "magiskboot",
    "sload_f2fs",
    "resize2fs",
    "fastbootd",
    "bu",
    "pigz",
    "unzip",
)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def load_elf_audit(directory: Path):
    module_path = directory / "elf_audit.py"
    spec = importlib.util.spec_from_file_location("hybrid_verify_elf_audit", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import ELF helper: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def text_entry(entries: dict[str, newc.Entry], name: str) -> str:
    require(name in entries, f"missing final text entry: {name}")
    try:
        return entries[name].data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"non-UTF-8 final text entry: {name}") from exc


def validate_fstab(text: str, name: str) -> None:
    targets = {
        "system": ("/dev/block/bootdevice/by-name/system", "/system_root"),
        "vendor": ("/dev/block/bootdevice/by-name/vendor", "/vendor"),
        "odm": ("/dev/block/bootdevice/by-name/odm", "/odm"),
    }
    for partition, (device, mount) in targets.items():
        rows = []
        device_rows = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split()
            if len(fields) >= 5 and fields[0] == device:
                device_rows.append(fields)
                if fields[1] == mount:
                    rows.append(fields)
        require(
            [row[2] for row in rows] == ["ext4", "erofs"],
            f"{name} does not contain ordered ext4+erofs alternatives for {partition}",
        )
        require(
            all(row[1] == mount for row in device_rows),
            f"{name} contains an unexpected {partition} mount point",
        )
        require(
            all("logical" not in row[-1].split(",") for row in rows),
            f"{name} has a logical {partition} alternative on a physical-A/B target",
        )
        require(
            all("slotselect" in row[-1].split(",") for row in rows),
            f"{name} has a non-slotselected {partition} alternative",
        )
        require(rows[0][3].startswith("ro"), f"{name} ext4 {partition} alternative is not read-only")
        require(rows[1][3].startswith("ro"), f"{name} erofs {partition} alternative is not read-only")

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 5:
            require(
                "logical" not in fields[-1].split(","),
                f"{name} retains logical recovery row: {stripped}",
            )
            require(
                fields[0] not in {"system", "vendor", "odm", "product", "my_product", "my_engineering"},
                f"{name} retains a name-only logical/subimage row: {stripped}",
            )
        require(
            len(fields) < 2
            or fields[1] not in {"/system_ext", "/product", "/my_product", "/my_engineering"},
            f"{name} contains a speculative logical/ColorOS subimage mount: {stripped}",
        )


def validate_twrp_flags(text: str, name: str) -> None:
    expected = {
        "/system_root": ("ext4", "/dev/block/bootdevice/by-name/system"),
        "/system_image": ("emmc", "/dev/block/bootdevice/by-name/system"),
        "/vendor": ("ext4", "/dev/block/bootdevice/by-name/vendor"),
        "/vendor_image": ("emmc", "/dev/block/bootdevice/by-name/vendor"),
        "/odm": ("ext4", "/dev/block/bootdevice/by-name/odm"),
        "/odm_image": ("emmc", "/dev/block/bootdevice/by-name/odm"),
    }
    rows = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        require(len(fields) >= 3, f"malformed {name} row: {stripped}")
        mount = fields[0]
        require(mount not in rows, f"duplicate {name} mount point: {mount}")
        rows[mount] = fields
        require("logical" not in stripped, f"{name} contains a logical flag: {stripped}")
        require(
            mount not in {"/product", "/product_image", "/my_product", "/my_engineering", "/system_ext"},
            f"{name} contains a speculative logical/ColorOS subimage entry: {stripped}",
        )

    for mount, (fstype, device) in expected.items():
        require(mount in rows, f"{name} is missing physical static-A/B entry {mount}")
        row = rows[mount]
        require(row[1] == fstype, f"{name} has wrong type for {mount}: {row[1]}")
        require(row[2] == device, f"{name} has wrong device for {mount}: {row[2]}")
        require("slotselect" in row[-1].split(";") or "slotselect" in row[-1], f"{name} lost slotselect for {mount}")
        if fstype == "ext4":
            require("fsflags=ro" in row[-1], f"{name} does not force {mount} read-only")


def properties_without_adb_overrides(text: str) -> list[str]:
    adb_keys = {"ro.secure", "ro.adb.secure", "ro.debuggable", "persist.sys.usb.config"}
    result = []
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        key = stripped.split("=", 1)[0] if "=" in stripped and not stripped.startswith("#") else None
        if key not in adb_keys:
            result.append(line)
    return result

def validate_private_elfs(
    entries: dict[str, newc.Entry],
    private_manifest: dict,
    elf_module,
) -> dict:
    executable_records = [
        record
        for record in private_manifest["records"]
        if record["kind"] in ("entry_point", "helper", "optional_helper", "helper_symlink_target")
    ]
    library_records = [
        record
        for record in private_manifest["records"]
        if record["kind"] in {"library", "dlopen_root", "dlopen_dependency"}
    ]
    common_library_records = [record for record in library_records if record["kind"] == "library"]
    dlopen_root_records = [record for record in library_records if record["kind"] == "dlopen_root"]
    dlopen_dependency_records = [
        record for record in library_records if record["kind"] == "dlopen_dependency"
    ]
    expected_common_libraries = {record["target"] for record in common_library_records}
    expected_all_libraries = {record["target"] for record in library_records}

    parsed_executables = {}
    parsed_libraries = {}
    with tempfile.TemporaryDirectory(prefix="hybrid-elf-verify-") as raw_temp:
        temp = Path(raw_temp)
        for record in executable_records + library_records:
            require(record["target"] in entries, f"manifested private ELF is missing: {record['target']}")
            entry = entries[record["target"]]
            if entry.data[:4] != b"\x7fELF":
                continue
            path = temp / record["target"].replace("/", "_")
            path.write_bytes(entry.data)
            elf = elf_module.Elf(path)
            if record["kind"] in ("entry_point", "helper", "optional_helper", "helper_symlink_target"):
                parsed_executables[record["target"]] = elf
            else:
                parsed_libraries[record["target"]] = elf

        require("system/tw/bin/recovery" in parsed_executables, "private recovery is not ELF")
        for target, elf in parsed_executables.items():
            if elf.interpreter is not None:
                require(
                    elf.interpreter == "/system/tw/linker64",
                    f"{target} still uses non-private PT_INTERP {elf.interpreter!r}",
                )
            require(elf.bits == 64, f"{target} is not ELF64")
        require(
            set(parsed_libraries) == expected_all_libraries,
            "a manifested private library is absent or not ELF",
        )
        for target, elf in parsed_libraries.items():
            require(elf.bits == 64, f"{target} is not ELF64")
            require(elf.interpreter is None, f"private shared library has PT_INTERP: {target}")

        by_name = defaultdict(list)
        for target, elf in parsed_libraries.items():
            by_name[Path(target).name].append((target, elf))
            if elf.soname and elf.soname != Path(target).name:
                by_name[elf.soname].append((target, elf))
        for name, candidates in by_name.items():
            candidates.sort()
            require(
                len({target for target, _elf in candidates}) == 1,
                f"ambiguous private library name/SONAME {name!r}: {[target for target, _elf in candidates]}",
            )

        def resolve_group(target: str, root_elf):
            selected = {}
            queue = deque(root_elf.needed)
            while queue:
                needed = queue.popleft()
                if needed in selected:
                    continue
                candidates = by_name.get(needed)
                require(bool(candidates), f"private DT_NEEDED {needed!r} is missing for {target}")
                library_target, library = candidates[0]
                selected[needed] = (library_target, library)
                queue.extend(library.needed)

            exports = set(root_elf.defined)
            for _library_target, library in selected.values():
                exports.update(library.defined)
            group_unresolved = {}
            missing = sorted(root_elf.undefined_strong - exports)
            if missing:
                group_unresolved[target] = missing
            for library_target, library in selected.values():
                missing = sorted(library.undefined_strong - exports)
                if missing:
                    group_unresolved[f"{target} -> {library_target}"] = missing
            return selected, group_unresolved

        selected_union = set()
        unresolved = {}
        per_executable_counts = {}
        for target, executable in sorted(parsed_executables.items()):
            selected, group_unresolved = resolve_group(target, executable)
            selected_targets = {item[0] for item in selected.values()}
            selected_union.update(selected_targets)
            per_executable_counts[target] = len(selected_targets)
            unresolved.update(group_unresolved)

        dlopen_report = None
        dlopen_section = private_manifest.get("dlopen_root")
        if dlopen_section is None:
            require(not dlopen_root_records, "unconfigured dlopen-root library record is present")
            require(not dlopen_dependency_records, "unconfigured dlopen dependency record is present")
            require(
                selected_union == expected_common_libraries,
                "private library set is not the exact union closure: "
                f"missing={sorted(expected_common_libraries - selected_union)}, "
                f"extra={sorted(selected_union - expected_common_libraries)}",
            )
        else:
            require(len(dlopen_root_records) == 1, "expected exactly one dlopen-root record")
            root_target = dlopen_section.get("root_target")
            require(
                root_target == dlopen_root_records[0]["target"],
                "dlopen-root target does not match its record",
            )
            require(root_target in parsed_libraries, "dlopen-root target is not an ELF library")
            root_elf = parsed_libraries[root_target]
            require(
                set(h40_dlopen.REQUIRED_ROOT_SYMBOLS).issubset(root_elf.defined),
                "dlopen root lacks the adapter's required dlsym ABI",
            )
            dlopen_selected, dlopen_unresolved = resolve_group(root_target, root_elf)
            dlopen_targets = {item[0] for item in dlopen_selected.values()}
            unresolved.update(dlopen_unresolved)
            require(
                dlopen_targets == set(dlopen_section.get("dependency_targets", [])),
                "dlopen-root dependency target closure differs from its manifest",
            )
            require(
                {root_target} | dlopen_targets == set(dlopen_section.get("load_group_targets", [])),
                "dlopen-root full load group differs from its manifest",
            )
            require(
                len(dlopen_selected) == dlopen_section.get("dt_needed_closure_count"),
                "dlopen-root DT_NEEDED closure count differs from its manifest",
            )
            resolution_rows = dlopen_section.get("needed_resolution", [])
            require(isinstance(resolution_rows, list), "dlopen-root resolution manifest is malformed")
            require(
                all(isinstance(row, dict) for row in resolution_rows),
                "dlopen-root resolution manifest contains a non-object row",
            )
            resolution_by_needed = {row.get("needed"): row for row in resolution_rows}
            require(
                len(resolution_by_needed) == len(resolution_rows),
                "dlopen-root resolution manifest contains duplicate needed names",
            )
            computed_resolution = {
                needed: library_target
                for needed, (library_target, _library) in dlopen_selected.items()
            }
            require(
                {needed: row.get("target") for needed, row in resolution_by_needed.items()}
                == computed_resolution,
                "dlopen-root needed-name resolution differs from its manifest",
            )
            for needed, row in resolution_by_needed.items():
                target_basename = Path(row["target"]).name
                expected_provenance = (
                    "stock_manifest"
                    if target_basename in h40_dlopen.EXPECTED_FILES
                    else "twrp"
                )
                require(
                    row.get("provenance") == expected_provenance,
                    f"dlopen-root dependency has bad provenance for {needed}",
                )
            expected_dependencies = expected_common_libraries | {
                record["target"] for record in dlopen_dependency_records
            }
            complete_union = selected_union | dlopen_targets
            require(
                complete_union == expected_dependencies,
                "private executable + dlopen dependency set is not the exact union closure: "
                f"missing={sorted(expected_dependencies - complete_union)}, "
                f"extra={sorted(complete_union - expected_dependencies)}",
            )
            require(
                expected_all_libraries == expected_dependencies | {root_target},
                "private library set contains a file outside executable/dlopen roots and dependencies",
            )
            dlopen_report = {
                "root_target": root_target,
                "dependency_library_count": len(dlopen_targets),
                "load_group_library_count": len(dlopen_targets) + 1,
                "required_root_symbols": list(h40_dlopen.REQUIRED_ROOT_SYMBOLS),
                "unresolved_strong_symbol_groups": len(dlopen_unresolved),
            }
        require(not unresolved, f"private ELF load groups have unresolved strong symbols: {unresolved}")

    result = {
        "dynamic_or_static_elf_executables": len(parsed_executables),
        "exact_library_count": len(expected_all_libraries),
        "per_executable_library_counts": per_executable_counts,
        "unresolved_strong_symbol_groups": len(unresolved),
    }
    if dlopen_report is not None:
        result["dlopen_root"] = dlopen_report
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--twrp-cpio", type=Path, required=True)
    parser.add_argument("--raw-cpio", type=Path, required=True)
    parser.add_argument("--gzip-cpio", type=Path, required=True)
    parser.add_argument("--private-manifest", type=Path, required=True)
    parser.add_argument("--stock-patch-manifest", type=Path, required=True)
    parser.add_argument("--elf-audit-dir", type=Path, required=True)
    parser.add_argument("--dlopen-root-manifest", type=Path)
    parser.add_argument("--h40-cryptoeng-overlay", type=Path)
    parser.add_argument("--h40-cryptoeng-manifest", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-compressed-bytes", type=int, default=45_000_000)
    args = parser.parse_args()

    private_manifest = json.loads(args.private_manifest.read_text(encoding="utf-8"))
    patch_manifest = json.loads(args.stock_patch_manifest.read_text(encoding="utf-8"))
    external_dlopen_manifest = None
    if args.dlopen_root_manifest is not None:
        try:
            external_dlopen_manifest = h40_dlopen.load_manifest(args.dlopen_root_manifest)
        except (OSError, h40_dlopen.ManifestError) as exc:
            raise SystemExit(f"invalid H.40 dlopen-root manifest: {exc}") from exc
    require(
        (args.h40_cryptoeng_overlay is None) == (args.h40_cryptoeng_manifest is None),
        "H.40 cryptoeng overlay and manifest must be supplied together",
    )
    h40_cryptoeng_manifest = None
    h40_cryptoeng_manifest_sha256 = None
    if args.h40_cryptoeng_manifest is not None:
        require(
            external_dlopen_manifest is not None,
            "H.40 stock-service dependency requires the explicit dlopen-root adapter opt-in",
        )
        try:
            h40_cryptoeng_manifest, h40_cryptoeng_manifest_sha256 = h40_cryptoeng.load_manifest(
                args.h40_cryptoeng_manifest
            )
        except (OSError, h40_cryptoeng.DependencyError) as exc:
            raise SystemExit(f"invalid H.40 cryptoeng manifest: {exc}") from exc
        require(args.h40_cryptoeng_overlay.is_file(), "H.40 cryptoeng overlay is absent")
        require(
            file_sha256(args.h40_cryptoeng_overlay)
            == h40_cryptoeng_manifest["overlay_sha256"],
            "H.40 cryptoeng overlay hash differs from its manifest",
        )
    require(
        (private_manifest.get("dlopen_root") is not None) == (external_dlopen_manifest is not None),
        "dlopen-root payload must be explicitly enabled in both build and verification",
    )
    require(
        private_manifest["stock_cpio_sha256"] == file_sha256(args.stock_cpio),
        "private overlay was made for a different stock cpio",
    )
    require(
        private_manifest["twrp_cpio_sha256"] == file_sha256(args.twrp_cpio),
        "private overlay was made for a different TWRP cpio",
    )
    require(
        patch_manifest["stock_cpio_sha256"] == file_sha256(args.stock_cpio),
        "stock patch overlay was made for a different stock cpio",
    )
    require(
        patch_manifest.get("partition_layout") == "physical_static_ab",
        "stock patch manifest is not for guacamole's physical static-A/B layout",
    )

    stock_list = newc.read(args.stock_cpio)
    final_list = newc.read(args.raw_cpio)
    require(len(stock_list) == len(newc.index(stock_list)), "stock cpio contains duplicate paths")
    require(len(final_list) == len(newc.index(final_list)), "final cpio contains duplicate paths")
    stock = newc.index(stock_list)
    final = newc.index(final_list)
    h40_cryptoeng_overlay_entries: dict[str, newc.Entry] = {}
    if args.h40_cryptoeng_overlay is not None:
        h40_cryptoeng_overlay_list = newc.read(args.h40_cryptoeng_overlay)
        require(
            len(h40_cryptoeng_overlay_list) == len(newc.index(h40_cryptoeng_overlay_list)),
            "H.40 cryptoeng overlay contains duplicate paths",
        )
        h40_cryptoeng_overlay_entries = newc.index(h40_cryptoeng_overlay_list)
        require(
            set(h40_cryptoeng_overlay_entries) == {h40_cryptoeng.TARGET},
            "H.40 cryptoeng overlay does not contain exactly its linker-visible library",
        )

    dlopen_section = private_manifest.get("dlopen_root")
    proprietary_record_kinds = {"dlopen_root", "dlopen_dependency"}
    proprietary_records = [
        record
        for record in private_manifest["records"]
        if record["kind"] in proprietary_record_kinds
    ]
    private_h40_targets = {
        f"system/tw/lib64/{name}" for name in h40_dlopen.EXPECTED_FILES
    }
    if external_dlopen_manifest is None:
        require(not proprietary_records, "H.40 proprietary records exist without explicit opt-in")
        require(
            not (private_h40_targets & {record["target"] for record in private_manifest["records"]}),
            "H.40 proprietary target exists without explicit opt-in",
        )
    else:
        try:
            validated_stock_blobs = h40_dlopen.validate_stock_entries(external_dlopen_manifest, stock)
        except h40_dlopen.ManifestError as exc:
            raise SystemExit(f"stock CPIO does not match the H.40 dlopen-root manifest: {exc}") from exc
        require(isinstance(dlopen_section, dict), "private dlopen-root manifest section is malformed")
        require(
            dlopen_section.get("manifest_sha256") == external_dlopen_manifest.raw_sha256,
            "private overlay used a different dlopen-root manifest",
        )
        require(
            dlopen_section.get("source_rom") == h40_dlopen.EXPECTED_ROM
            and dlopen_section.get("source_boot_sha256") == h40_dlopen.EXPECTED_BOOT_SHA256,
            "private dlopen-root source identity is not H.40",
        )
        require(
            dlopen_section.get("destination_directory") == h40_dlopen.DESTINATION_DIRECTORY,
            "private dlopen-root destination escaped the private runtime",
        )
        require(
            dlopen_section.get("root_target")
            == f"system/tw/lib64/{h40_dlopen.ROOT_LIBRARY}",
            "private dlopen-root target is wrong",
        )
        require(
            dlopen_section.get("required_root_symbols") == list(h40_dlopen.REQUIRED_ROOT_SYMBOLS),
            "private dlopen-root ABI symbol allow-list changed",
        )
        require(
            set(dlopen_section.get("proprietary_targets", [])) == private_h40_targets,
            "private dlopen-root proprietary target set is not the pinned five",
        )
        require(len(proprietary_records) == len(h40_dlopen.EXPECTED_FILES), "wrong proprietary record count")
        proprietary_by_target = {record["target"]: record for record in proprietary_records}
        require(
            len(proprietary_by_target) == len(proprietary_records)
            and set(proprietary_by_target) == private_h40_targets,
            "proprietary records are not a unique exact five-file target set",
        )
        pinned_target_by_digest = {
            item.sha256: item.target for item in external_dlopen_manifest.files
        }
        for record in private_manifest["records"]:
            digest = record.get("target_sha256")
            if digest in pinned_target_by_digest:
                require(
                    record["target"] == pinned_target_by_digest[digest],
                    f"pinned H.40 bytes escaped the private allow-listed target: {record['target']}",
                )
        for item in external_dlopen_manifest.files:
            record = proprietary_by_target[item.target]
            expected_kind = "dlopen_root" if item.name == h40_dlopen.ROOT_LIBRARY else "dlopen_dependency"
            require(record["kind"] == expected_kind, f"wrong dlopen role for {item.name}")
            require(record.get("provenance") == "stock_cpio_hash_pinned", f"bad provenance for {item.name}")
            require(record.get("source") == item.source, f"bad stock source path for {item.name}")
            require(record.get("source_sha256") == item.sha256, f"bad source digest for {item.name}")
            require(record.get("target_sha256") == item.sha256, f"bad target digest for {item.name}")
            require(record.get("bytes") == item.bytes, f"bad manifested size for {item.name}")
            require(item.target in final, f"final ramdisk is missing {item.target}")
            source_entry = validated_stock_blobs[item.name]
            target_entry = final[item.target]
            require(target_entry.data == source_entry.data, f"private H.40 blob is not copied from stock: {item.name}")
            require(
                (
                    target_entry.mode,
                    target_entry.uid,
                    target_entry.gid,
                    target_entry.mtime,
                    target_entry.devmajor,
                    target_entry.devminor,
                    target_entry.rdevmajor,
                    target_entry.rdevminor,
                )
                == (
                    source_entry.mode,
                    source_entry.uid,
                    source_entry.gid,
                    source_entry.mtime,
                    source_entry.devmajor,
                    source_entry.devminor,
                    source_entry.rdevmajor,
                    source_entry.rdevminor,
                ),
                f"private H.40 blob metadata was not cloned from stock: {item.name}",
            )
            require(
                final[item.source] == source_entry,
                f"stock runtime copy changed while seeding private H.40 blob: {item.source}",
            )
        require(
            dlopen_section.get("unresolved_strong_symbol_groups") == 0,
            "builder reported unresolved H.40 dlopen-root symbols",
        )

    replacements = {
        record["target"]: record
        for record in patch_manifest["records"]
        if record["kind"] == "replacement"
    }
    additions = {
        record["target"]: record
        for record in patch_manifest["records"]
        if record["kind"] == "addition"
    }
    private_records = {
        record["target"]: record
        for record in private_manifest["records"]
    }
    require(
        len(private_records) == len(private_manifest["records"]),
        "private manifest contains duplicate targets",
    )
    require(
        private_manifest.get("library_count")
        == sum(
            record["kind"] in {"library", "dlopen_root", "dlopen_dependency"}
            for record in private_manifest["records"]
        ),
        "private manifest library count is inconsistent",
    )
    private_directories = {"system/tw", "system/tw/bin", "system/tw/lib64"}
    h40_cryptoeng_targets = (
        {h40_cryptoeng.TARGET} if h40_cryptoeng_manifest is not None else set()
    )
    require(
        h40_cryptoeng.TARGET not in replacements
        and h40_cryptoeng.TARGET not in additions
        and h40_cryptoeng.TARGET not in private_records,
        "H.40 CommonDCS target may be owned only by its explicit overlay",
    )

    for name, source in stock.items():
        require(name in final, f"stock entry disappeared: {name}")
        target = final[name]
        if name in replacements:
            expected = replacements[name]
            require(sha256(target.data) == expected["target_sha256"], f"wrong patched data for {name}")
            require(
                replace(target, data=source.data) == source,
                f"metadata changed while patching stock entry {name}",
            )
        else:
            require(target == source, f"unapproved stock entry changed: {name}")

    for name, record in additions.items():
        require(name not in stock, f"declared addition overwrites stock path: {name}")
        require(name in final, f"declared stock-side addition is missing: {name}")
        require(sha256(final[name].data) == record["target_sha256"], f"wrong addition data for {name}")
    for name, record in private_records.items():
        require(name in final, f"private overlay target is missing: {name}")
        require(sha256(final[name].data) == record["target_sha256"], f"wrong private data for {name}")

    if h40_cryptoeng_manifest is not None:
        require(h40_cryptoeng.TARGET not in stock, "H.40 CommonDCS overlay overwrites stock")
        require(h40_cryptoeng.TARGET in final, "final ramdisk is missing H.40 CommonDCS")
        require(
            final[h40_cryptoeng.TARGET] == h40_cryptoeng_overlay_entries[h40_cryptoeng.TARGET],
            "merged H.40 CommonDCS entry differs from its one-file overlay",
        )
    for name, entry in final.items():
        if sha256(entry.data) == h40_cryptoeng.SOURCE_SHA256:
            require(
                h40_cryptoeng_manifest is not None and name == h40_cryptoeng.TARGET,
                f"pinned H.40 CommonDCS bytes escaped their sole target: {name}",
            )

    expected_paths = (
        set(stock)
        | set(additions)
        | set(private_records)
        | private_directories
        | h40_cryptoeng_targets
    )
    require(
        set(final) == expected_paths,
        f"unexpected final path set: missing={sorted(expected_paths - set(final))}, "
        f"extra={sorted(set(final) - expected_paths)}",
    )

    init_rc = text_entry(final, "system/etc/init/init.rc")
    require(init_rc.count("service recovery /system/tw/bin/recovery") == 1, "private recovery service missing")
    require("service recovery /system/bin/recovery" not in init_rc, "stock recovery service still active")
    require(init_rc.count("service fastbootd /system/tw/bin/fastbootd") == 1, "private fastbootd service missing")
    if h40_cryptoeng_manifest is not None:
        require("service common_dcs " not in init_rc, "a CommonDCS daemon was added to final init")
        require(
            "system/bin/common_dcs" not in final and "system_ext/bin/common_dcs" not in final,
            "a CommonDCS daemon binary was added to the final ramdisk",
        )
    require(
        final["system/bin/recovery"] == stock["system/bin/recovery"],
        "stock /system/bin/recovery sentinel changed; init may stop detecting recovery mode",
    )
    require(
        final["system_ext"] == stock["system_ext"],
        "root system_ext symlink changed",
    )
    require(
        final["first_stage_ramdisk/fstab.qcom"] == stock["first_stage_ramdisk/fstab.qcom"],
        "stock first-stage fstab changed; ColorOS loop-mounted subimages must remain dormant and intact",
    )

    linker_config = text_entry(final, "system/etc/ld.config.txt")
    require(linker_config.count("dir.twrp = /system/tw/bin") == 1, "bad private linker dir mapping")
    require(len(re.findall(r"^\[twrp\]\s*$", linker_config, re.MULTILINE)) == 1, "bad TWRP linker section")
    require(
        linker_config.count("namespace.default.search.paths = /system/tw/${LIB}") == 1,
        "bad private library namespace",
    )

    for fstab in ("etc/recovery.fstab", "system/etc/recovery.fstab"):
        validate_fstab(text_entry(final, fstab), fstab)
    for contexts in ("plat_file_contexts", "system/etc/selinux/plat_file_contexts"):
        content = text_entry(final, contexts)
        for expression in (
            "/system/tw/linker64",
            "/system/tw/bin(/.*)?",
            "/system/tw/lib64(/.*)?",
        ):
            require(content.count(expression) == 1, f"bad private SELinux context in {contexts}: {expression}")

    for flags_name in ("etc/twrp.flags", "system/etc/twrp.flags"):
        validate_twrp_flags(text_entry(final, flags_name), flags_name)

    properties = text_entry(final, "prop.default")
    require(
        not re.search(r"^ro\.boot\.dynamic_partitions=", properties, re.MULTILINE),
        "dynamic-partition property was injected into static-A/B prop.default",
    )
    require(
        properties_without_adb_overrides(properties)
        == properties_without_adb_overrides(text_entry(stock, "prop.default")),
        "a non-ADB stock property changed",
    )
    require(
        not re.search(r"^ro\.boot\.dynamic_partitions_retrofit=", properties, re.MULTILINE),
        "retrofit dynamic-partition property was injected into static-A/B prop.default",
    )

    routes = private_manifest["helper_routes"]
    by_source = {route["source"]: route for route in routes}
    for helper in MANDATORY_HELPERS:
        absolute = f"system/bin/{helper}"
        private = f"system/tw/bin/{helper}"
        require(absolute in final, f"mandatory absolute helper route is missing: /{absolute}")
        require(private in final, f"mandatory private helper is missing: /{private}")
        require(absolute in by_source, f"mandatory helper route is unmanifested: /{absolute}")
        route = by_source[absolute]
        if route["routing"] == "stock_shell_exec_private":
            require(
                final[absolute].data == (
                    "#!/system/bin/sh\n" f'exec /system/tw/bin/{helper} "$@"\n'
                ).encode("ascii"),
                f"unsafe helper wrapper contents: /{absolute}",
            )
    require(
        by_source["system/bin/minadbd"]["private_target"] == "system/tw/bin/minadbd",
        "ADB sideload does not route /system/bin/minadbd to the private runtime",
    )
    for asset in private_manifest.get("original_assets_included", []):
        require(asset in final and asset not in stock, f"TWRP app integration asset is missing: /{asset}")

    recovery_record = next(
        (
            record
            for record in private_manifest["records"]
            if record["kind"] == "entry_point" and record["target"] == "system/tw/bin/recovery"
        ),
        None,
    )
    require(recovery_record is not None, "private recovery entry-point manifest is missing")
    cstring_patches = recovery_record.get("exact_cstring_patches", [])
    require(
        cstring_patches
        and all(patch["source"] == "/system/bin/recovery" for patch in cstring_patches)
        and all(patch["target"] == "/system/tw/bin/r" for patch in cstring_patches),
        "recovery self-exec path patch is absent or unmanifested",
    )
    recovery_blob = final["system/tw/bin/recovery"].data
    require(
        b"/system/bin/recovery\0" not in recovery_blob,
        "private recovery can still self-exec the stock recovery path",
    )
    require(
        b"/system/tw/bin/r\0" in recovery_blob,
        "private recovery self-exec alias is missing",
    )
    alias = final.get("system/tw/bin/r")
    require(
        alias is not None and alias.mode & 0o170000 == 0o120000 and alias.data == b"recovery",
        "private recovery self-exec alias is not the expected relative symlink",
    )

    elf_module = load_elf_audit(args.elf_audit_dir)
    h40_cryptoeng_report = None
    if h40_cryptoeng_manifest is not None:
        try:
            h40_cryptoeng_report = h40_cryptoeng.validate_final(
                stock, final, h40_cryptoeng_manifest, elf_module
            )
        except h40_cryptoeng.DependencyError as exc:
            raise SystemExit(f"invalid final H.40 cryptoeng dependency: {exc}") from exc
    elf_report = validate_private_elfs(final, private_manifest, elf_module)

    raw = args.raw_cpio.read_bytes()
    compressed = args.gzip_cpio.read_bytes()
    require(len(raw) % 256 == 0, "raw newc archive is not 256-byte aligned")
    require(compressed[:2] == b"\x1f\x8b", "output payload is not gzip")
    require(compressed[4:8] == b"\0\0\0\0", "gzip timestamp is not deterministic zero")
    require(gzip.decompress(compressed) == raw, "gzip payload does not exactly reconstruct raw cpio")
    require(
        len(compressed) <= args.max_compressed_bytes,
        f"compressed payload {len(compressed)} exceeds limit {args.max_compressed_bytes}",
    )

    report = {
        "format": 1,
        "partition_layout": "physical_static_ab",
        "stock_cpio_sha256": file_sha256(args.stock_cpio),
        "twrp_cpio_sha256": file_sha256(args.twrp_cpio),
        "raw_cpio_sha256": sha256(raw),
        "gzip_cpio_sha256": sha256(compressed),
        "stock_entry_count": len(stock),
        "final_entry_count": len(final),
        "approved_stock_replacements": sorted(replacements),
        "approved_stock_additions": sorted(additions),
        "private_record_count": len(private_records),
        "raw_bytes": len(raw),
        "gzip_bytes": len(compressed),
        "max_compressed_bytes": args.max_compressed_bytes,
        "elf": elf_report,
        "checks": {
            "all_unapproved_stock_entries_byte_and_metadata_identical": True,
            "private_pt_interp_only": True,
            "exact_private_elf_dependency_union": True,
            "zero_unresolved_private_strong_symbols": True,
            "absolute_helper_wrappers_route_private": True,
            "minadbd_sideload_route_private": True,
            "included_original_path_assets_verified": True,
            "recovery_self_exec_route_private": True,
            "dual_physical_static_ab_ext4_erofs_including_odm": True,
            "no_logical_product_or_coloros_subimage_rows": True,
            "embedded_system_ext_symlink_preserved": True,
            "stock_first_stage_loop_mount_fstab_preserved": True,
            "stock_recovery_mode_sentinel_preserved": True,
            "no_dynamic_partition_property_injection": True,
            "all_non_adb_stock_properties_preserved": True,
            "stock_selinux_policy_preserved": True,
            "deterministic_gzip_roundtrip": True,
        },
    }
    if external_dlopen_manifest is not None:
        report["dlopen_root_manifest_sha256"] = external_dlopen_manifest.raw_sha256
        report["checks"].update(
            {
                "h40_five_blob_manifest_hashes_verified": True,
                "h40_blobs_copied_only_from_stock_cpio": True,
                "h40_blobs_confined_to_private_runtime": True,
                "h40_dlopen_full_dt_needed_closure": True,
                "h40_dlopen_zero_unresolved_strong_symbols": True,
                "stock_h40_runtime_copies_preserved": True,
            }
        )
    if h40_cryptoeng_report is not None:
        report["h40_cryptoeng_manifest_sha256"] = h40_cryptoeng_manifest_sha256
        report["h40_cryptoeng_dependency"] = h40_cryptoeng_report
        report["approved_h40_cryptoeng_additions"] = [h40_cryptoeng.TARGET]
        report["checks"].update(
            {
                "h40_cryptoeng_exact_system_ext_hash_verified": True,
                "h40_cryptoeng_stock_namespace_placement_verified": True,
                "h40_cryptoeng_recursive_dt_needed_closure_verified": True,
                "h40_cryptoeng_service_import_resolved": True,
                "h40_cryptoeng_stock_init_sequence_verified": True,
                "no_common_dcs_daemon_added": True,
            }
        )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
