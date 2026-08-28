#!/usr/bin/env python3
"""Build a private-runtime TWRP overlay from a raw recovery ramdisk.

Only the requested entry-point ELF files, a functional helper set, their exact
recursive DT_NEEDED closure, the matching TWRP dynamic linker, and /twres are
copied.  Executables are moved under /system/tw and their PT_INTERP program
header is changed without performing an unsafe global byte-string replacement.
Missing absolute /system/bin helper paths are supplied by tiny stock-shell
wrappers which exec the private copy.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from collections import defaultdict, deque
from dataclasses import replace
from pathlib import Path, PurePosixPath

import newc
import h40_dlopen


PRIVATE_INTERPRETER = "/system/tw/linker64"

# These paths are required for sideload, ramdisk repacking, dynamic-partition
# fastboot, ext4/f2fs image handling, backup compression, and ZIP extraction.
DEFAULT_REQUIRED_HELPERS = (
    "system/bin/minadbd",
    "system/bin/magiskboot",
    "system/bin/sload_f2fs",
    "system/bin/resize2fs",
    "system/bin/fastbootd",
    "system/bin/bu",
    "system/bin/pigz",
    "system/bin/unzip",
)

# Optional filesystem/ROM helpers are included when the selected build ships
# them.  Missing optional paths never make the build fail.
DEFAULT_OPTIONAL_HELPERS = (
    "system/bin/avbctl",
    "system/bin/bc",
    "system/bin/dump_image",
    "system/bin/erase_image",
    "system/bin/exfat-fuse",
    "system/bin/fatlabel",
    "system/bin/flash_image",
    "system/bin/fsck.exfat",
    "system/bin/fsck.fat",
    "system/bin/fsck.ntfs",
    "system/bin/fscryptpolicyget",
    "system/bin/mkexfatfs",
    "system/bin/mkfs.fat",
    "system/bin/mkfs.ntfs",
    "system/bin/mount.ntfs",
    "system/bin/ozip_decrypt",
    "system/bin/resetprop",
    "system/bin/tune2fs",
    "system/bin/twrp",
    "system/bin/unpigz",
    "system/bin/zipinfo",
)

DEFAULT_ORIGINAL_ASSETS = (
    "system/bin/me.twrp.twrpapp.apk",
    "system/bin/privapp-permissions-twrpapp.xml",
)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_elf_audit(directory: Path):
    module_path = directory / "elf_audit.py"
    if not module_path.is_file():
        raise SystemExit(f"missing ELF helper: {module_path}")
    spec = importlib.util.spec_from_file_location("hybrid_elf_audit", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import ELF helper: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def resolve_closure(root: Path, binaries: list[str], elf_module):
    parsed_binaries = []
    bits = None
    for relative in binaries:
        path = root / PurePosixPath(relative)
        elf = elf_module.Elf(path)
        if bits is None:
            bits = elf.bits
        elif elf.bits != bits:
            raise SystemExit("mixed 32-bit and 64-bit entry points are not supported")
        parsed_binaries.append((relative, path, elf))
    if bits != 64:
        raise SystemExit(f"expected a 64-bit TWRP recovery, got ELF{bits}")

    index = defaultdict(list)
    for path, elf in elf_module.iter_elfs(root):
        if elf.bits != bits:
            continue
        relative = path.relative_to(root).as_posix()
        row = (relative, path, elf)
        index[path.name].append(row)
        if elf.soname and elf.soname != path.name:
            index[elf.soname].append(row)

    def rank(row):
        relative = row[0]
        location = 0 if relative.startswith("system/lib64/") else 1 if relative.startswith("vendor/lib64/") else 2
        return location, len(relative), relative

    for rows in index.values():
        rows.sort(key=rank)

    selected = {}
    requested_by: dict[str, str] = {}
    queue = deque()
    for relative, _path, elf in parsed_binaries:
        for needed in elf.needed:
            queue.append((needed, relative))
    while queue:
        name, requester = queue.popleft()
        if name in selected:
            continue
        candidates = index.get(name)
        if not candidates:
            raise SystemExit(f"missing DT_NEEDED library {name!r}, requested by {requester}")
        relative, path, elf = candidates[0]
        selected[name] = (relative, path, elf)
        requested_by[name] = requester
        for child in elf.needed:
            queue.append((child, relative))
    return parsed_binaries, selected, requested_by


def resolve_dlopen_root(
    twrp_root: Path,
    stock_tree: Path,
    stock_entries: dict[str, newc.Entry],
    manifest_path: Path,
    elf_module,
):
    """Resolve the pinned H.40 root against pinned blobs + the TWRP runtime.

    The stock tree is used only as a parser view after each byte sequence has
    been proven equal to its stock-CPIO entry.  Arbitrary stock libraries are
    never candidates: the manifest's exact five files are the complete stock
    allow-list, and all remaining candidates come from the TWRP tree.
    """

    try:
        manifest = h40_dlopen.load_manifest(manifest_path)
        stock_blobs = h40_dlopen.validate_stock_entries(manifest, stock_entries)
    except (OSError, h40_dlopen.ManifestError) as exc:
        raise SystemExit(f"invalid H.40 dlopen-root manifest/payload: {exc}") from exc

    proprietary = {}
    for item in manifest.files:
        source_entry = stock_blobs[item.name]
        ensure_tree_matches_archive(stock_tree, item.source, source_entry)
        source_path = stock_tree / PurePosixPath(item.source)
        parsed = elf_module.Elf(source_path)
        if parsed.bits != 64:
            raise SystemExit(f"pinned H.40 blob is not ELF64: {item.source}")
        if parsed.interpreter is not None:
            raise SystemExit(f"pinned H.40 shared library unexpectedly has PT_INTERP: {item.source}")
        if parsed.soname != item.name:
            raise SystemExit(
                f"pinned H.40 blob SONAME mismatch for {item.source}: {parsed.soname!r}"
            )
        proprietary[item.name] = (item.source, source_path, parsed, source_entry, item)

    root_row = proprietary[h40_dlopen.ROOT_LIBRARY]
    root_elf = root_row[2]
    missing_symbols = sorted(set(h40_dlopen.REQUIRED_ROOT_SYMBOLS) - root_elf.defined)
    if missing_symbols:
        raise SystemExit(f"H.40 dlopen root lacks adapter ABI symbols: {missing_symbols}")

    index = defaultdict(list)
    # Pinned H.40 candidates deliberately rank before same-named TWRP files.
    for name, (relative, path, parsed, source_entry, item) in proprietary.items():
        row = (0, "stock_manifest", relative, path, parsed, source_entry, item)
        index[name].append(row)
        if parsed.soname and parsed.soname != name:
            index[parsed.soname].append(row)
    for path, parsed in elf_module.iter_elfs(twrp_root):
        if parsed.bits != 64:
            continue
        relative = path.relative_to(twrp_root).as_posix()
        row = (1, "twrp", relative, path, parsed, None, None)
        index[path.name].append(row)
        if parsed.soname and parsed.soname != path.name:
            index[parsed.soname].append(row)

    def rank(row):
        priority, _provenance, relative, _path, _parsed, _entry, _item = row
        location = 0 if relative.startswith("system/lib64/") else 1 if relative.startswith("vendor/lib64/") else 2
        return priority, location, len(relative), relative

    for rows in index.values():
        rows.sort(key=rank)

    selected = {}
    requested_by = {}
    queue = deque((needed, h40_dlopen.ROOT_LIBRARY) for needed in root_elf.needed)
    while queue:
        needed, requester = queue.popleft()
        if needed in selected:
            continue
        candidates = index.get(needed)
        if not candidates:
            raise SystemExit(f"H.40 dlopen root is missing DT_NEEDED {needed!r}, requested by {requester}")
        row = candidates[0]
        selected[needed] = row
        requested_by[needed] = requester
        for child in row[4].needed:
            queue.append((child, row[2]))

    used_proprietary = {h40_dlopen.ROOT_LIBRARY}
    used_proprietary.update(
        PurePosixPath(row[2]).name
        for row in selected.values()
        if row[1] == "stock_manifest"
    )
    if used_proprietary != h40_dlopen.EXPECTED_FILES:
        raise SystemExit(
            "pinned H.40 payload is not the exact proprietary dependency closure: "
            f"missing={sorted(h40_dlopen.EXPECTED_FILES - used_proprietary)}, "
            f"extra={sorted(used_proprietary - h40_dlopen.EXPECTED_FILES)}"
        )

    exports = set(root_elf.defined)
    for row in selected.values():
        exports.update(row[4].defined)
    unresolved = {}
    missing = sorted(root_elf.undefined_strong - exports)
    if missing:
        unresolved[h40_dlopen.ROOT_LIBRARY] = missing
    for needed, row in selected.items():
        missing = sorted(row[4].undefined_strong - exports)
        if missing:
            unresolved[f"{needed} ({row[2]})"] = missing
    if unresolved:
        raise SystemExit(f"H.40 dlopen load group has unresolved strong symbols: {unresolved}")

    return {
        "manifest": manifest,
        "proprietary": proprietary,
        "root": root_row,
        "selected": selected,
        "requested_by": requested_by,
        "unresolved": unresolved,
    }


def patch_pt_interp(blob: bytes, new_interpreter: str, expected_old: str | None = None) -> tuple[bytes, str]:
    if blob[:4] != b"\x7fELF":
        raise ValueError("entry point is not ELF")
    elf_class, encoding = blob[4], blob[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", blob, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
        ph_format = endian + "IIQQQQQQ"
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", blob, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
        ph_format = endian + "IIIIIIII"

    matches = []
    for number in range(phnum):
        offset = phoff + number * phentsize
        values = struct.unpack_from(ph_format, blob, offset)
        p_type = values[0]
        if p_type != 3:  # PT_INTERP
            continue
        if elf_class == 2:
            p_offset, p_filesz = values[2], values[5]
        else:
            p_offset, p_filesz = values[1], values[4]
        matches.append((p_offset, p_filesz))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one PT_INTERP segment, found {len(matches)}")

    offset, size = matches[0]
    segment = blob[offset : offset + size]
    if len(segment) != size:
        raise ValueError("truncated PT_INTERP segment")
    old_bytes = segment.split(b"\0", 1)[0]
    try:
        old_interpreter = old_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII PT_INTERP") from exc
    if expected_old is not None and old_interpreter != expected_old:
        raise ValueError(f"unexpected PT_INTERP {old_interpreter!r}; expected {expected_old!r}")
    new_bytes = new_interpreter.encode("ascii") + b"\0"
    if len(new_bytes) > size:
        raise ValueError(
            f"replacement interpreter needs {len(new_bytes)} bytes but PT_INTERP has only {size}"
        )

    patched = bytearray(blob)
    patched[offset : offset + size] = new_bytes + b"\0" * (size - len(new_bytes))
    # This assertion proves that no matching string outside PT_INTERP was touched.
    if patched[:offset] != blob[:offset] or patched[offset + size :] != blob[offset + size :]:
        raise AssertionError("bytes outside PT_INTERP changed")
    return bytes(patched), old_interpreter


def patch_exact_cstring(blob: bytes, old: str, new: str) -> tuple[bytes, int]:
    """Replace complete NUL-terminated C strings without shifting the ELF."""

    old_bytes = old.encode("ascii") + b"\0"
    new_bytes = new.encode("ascii") + b"\0"
    if len(new_bytes) > len(old_bytes):
        raise ValueError(f"replacement C string {new!r} is longer than {old!r}")
    replacement = new_bytes + b"\0" * (len(old_bytes) - len(new_bytes))
    patched = bytearray(blob)
    offsets = []
    cursor = 0
    while True:
        offset = blob.find(old_bytes, cursor)
        if offset < 0:
            break
        # Only a standalone C string is eligible; do not alter a substring of
        # another literal or arbitrary binary data.
        if offset == 0 or blob[offset - 1] == 0:
            offsets.append(offset)
            patched[offset : offset + len(old_bytes)] = replacement
        cursor = offset + 1
    if not offsets:
        raise ValueError(f"standalone C string {old!r} was not found")
    if len(patched) != len(blob):
        raise AssertionError("exact C-string patch changed ELF length")
    approved = set()
    for offset in offsets:
        approved.update(range(offset, offset + len(old_bytes)))
    unexpected = [index for index, pair in enumerate(zip(blob, patched)) if pair[0] != pair[1] and index not in approved]
    if unexpected:
        raise AssertionError(f"bytes outside exact C-string spans changed: {unexpected[:8]}")
    return bytes(patched), len(offsets)


def ensure_tree_matches_archive(tree_root: Path, relative: str, archive_entry: newc.Entry) -> None:
    tree_path = tree_root / PurePosixPath(relative)
    try:
        tree_blob = tree_path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"cannot read extracted tree path {tree_path}: {exc}") from exc
    if tree_blob != archive_entry.data:
        raise SystemExit(
            f"tree/cpio mismatch for {relative}: tree={sha256(tree_blob)}, cpio={sha256(archive_entry.data)}"
        )


def clone(entry: newc.Entry, target: str, data: bytes | None, ino: int) -> newc.Entry:
    return replace(
        entry,
        name=newc.normalize_name(target),
        ino=ino,
        nlink=1,
        data=entry.data if data is None else data,
    )


def is_symlink(entry: newc.Entry) -> bool:
    return entry.mode & 0o170000 == 0o120000


def is_regular(entry: newc.Entry) -> bool:
    return entry.mode & 0o170000 == 0o100000


def collect_helper_sources(
    source_entries: dict[str, newc.Entry],
    required: list[str],
    optional: list[str],
) -> tuple[list[str], list[str], dict[str, str]]:
    """Return requested helpers, recursively included symlink targets, and roles."""

    requested = []
    roles: dict[str, str] = {}
    for relative in required:
        relative = newc.normalize_name(relative)
        if relative not in source_entries:
            raise SystemExit(f"required TWRP helper is absent from cpio: {relative}")
        requested.append(relative)
        roles[relative] = "helper"
    for relative in optional:
        relative = newc.normalize_name(relative)
        if relative in source_entries:
            requested.append(relative)
            roles.setdefault(relative, "optional_helper")

    included = []
    queue = deque(requested)
    seen = set()
    while queue:
        relative = queue.popleft()
        if relative in seen:
            continue
        seen.add(relative)
        entry = source_entries[relative]
        included.append(relative)
        if not is_symlink(entry):
            continue
        try:
            target_text = entry.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"non-UTF-8 symlink target in {relative}") from exc
        if target_text.startswith("/"):
            target = newc.normalize_name(target_text)
        else:
            target = newc.normalize_name(str(PurePosixPath(relative).parent / target_text))
        if target not in source_entries:
            raise SystemExit(f"helper symlink {relative} points to missing {target}")
        roles.setdefault(target, "helper_symlink_target")
        queue.append(target)
    return requested, included, roles


def wrapper_for(private_basename: str) -> bytes:
    return (
        "#!/system/bin/sh\n"
        f'exec /system/tw/bin/{private_basename} "$@"\n'
    ).encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--twrp-tree", type=Path, required=True)
    parser.add_argument("--twrp-cpio", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--stock-tree", type=Path)
    parser.add_argument("--dlopen-root-manifest", type=Path)
    parser.add_argument("--elf-audit-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--entry-point", action="append", default=[])
    parser.add_argument("--required-helper", action="append", default=[])
    parser.add_argument("--optional-helper", action="append", default=[])
    parser.add_argument("--original-asset", action="append", default=[])
    args = parser.parse_args()

    entry_points = [newc.normalize_name(item) for item in (args.entry_point or ["system/bin/recovery"])]
    if len({PurePosixPath(item).name for item in entry_points}) != len(entry_points):
        raise SystemExit("entry-point basenames must be unique in /system/tw/bin")

    source_entries = newc.index(newc.read(args.twrp_cpio))
    stock_entries = newc.index(newc.read(args.stock_cpio))
    for relative in entry_points:
        if relative not in source_entries:
            raise SystemExit(f"entry point is absent from TWRP cpio: {relative}")

    required_helpers = args.required_helper or list(DEFAULT_REQUIRED_HELPERS)
    optional_helpers = args.optional_helper or list(DEFAULT_OPTIONAL_HELPERS)
    original_assets = list(DEFAULT_ORIGINAL_ASSETS) + [
        item for item in args.original_asset if newc.normalize_name(item) not in DEFAULT_ORIGINAL_ASSETS
    ]
    requested_helpers, included_helpers, helper_roles = collect_helper_sources(
        source_entries,
        required_helpers,
        optional_helpers,
    )

    private_sources = []
    private_roles = {}
    for relative in entry_points:
        if relative not in private_roles:
            private_sources.append(relative)
            private_roles[relative] = "entry_point"
    for relative in included_helpers:
        if relative not in private_roles:
            private_sources.append(relative)
            private_roles[relative] = helper_roles[relative]
    private_basenames = [PurePosixPath(relative).name for relative in private_sources]
    if len(private_basenames) != len(set(private_basenames)):
        duplicates = sorted(name for name in set(private_basenames) if private_basenames.count(name) > 1)
        raise SystemExit(f"private /system/tw/bin basename collision: {duplicates}")

    elf_sources = []
    parsed_by_source = {}
    elf_module = load_elf_audit(args.elf_audit_dir.resolve())
    for relative in private_sources:
        entry = source_entries[relative]
        if not is_regular(entry) or entry.data[:4] != b"\x7fELF":
            continue
        ensure_tree_matches_archive(args.twrp_tree, relative, entry)
        parsed = elf_module.Elf(args.twrp_tree / PurePosixPath(relative))
        if parsed.bits != 64:
            raise SystemExit(f"private helper is not ELF64: {relative}")
        elf_sources.append(relative)
        parsed_by_source[relative] = parsed
    parsed_binaries, selected, requested_by = resolve_closure(
        args.twrp_tree,
        elf_sources,
        elf_module,
    )
    # resolve_closure reparses the same objects; require identical dependency views.
    for relative, _path, parsed in parsed_binaries:
        if parsed.needed != parsed_by_source[relative].needed or parsed.interpreter != parsed_by_source[relative].interpreter:
            raise SystemExit(f"non-deterministic ELF parse for {relative}")

    dlopen = None
    if args.dlopen_root_manifest is not None:
        if args.stock_tree is None:
            raise SystemExit("--stock-tree is required with --dlopen-root-manifest")
        dlopen = resolve_dlopen_root(
            args.twrp_tree,
            args.stock_tree,
            stock_entries,
            args.dlopen_root_manifest,
            elf_module,
        )

    overlay: list[newc.Entry] = []
    next_ino = 700000
    for directory in ("system/tw", "system/tw/bin", "system/tw/lib64"):
        overlay.append(newc.directory(directory, ino=next_ino))
        next_ino += 1

    records = []
    interpreters = set()
    private_targets = {}
    for relative in private_sources:
        source = source_entries[relative]
        parsed = parsed_by_source.get(relative)
        target_data = source.data
        source_interpreter = None
        target_interpreter = None
        exact_cstring_patches = []
        if parsed is not None and parsed.interpreter is not None:
            target_data, source_interpreter = patch_pt_interp(
                source.data,
                PRIVATE_INTERPRETER,
                expected_old=parsed.interpreter,
            )
            if source_interpreter != "/system/bin/linker64":
                raise SystemExit(f"unsupported source interpreter for {relative}: {source_interpreter}")
            interpreters.add(source_interpreter)
            target_interpreter = PRIVATE_INTERPRETER
        if relative in entry_points and PurePosixPath(relative).name == "recovery":
            target_data, patch_count = patch_exact_cstring(
                target_data,
                "/system/bin/recovery",
                "/system/tw/bin/r",
            )
            exact_cstring_patches.append(
                {
                    "source": "/system/bin/recovery",
                    "target": "/system/tw/bin/r",
                    "count": patch_count,
                    "fixed_span_bytes": len("/system/bin/recovery") + 1,
                }
            )
        target = f"system/tw/bin/{PurePosixPath(relative).name}"
        # Relative symlinks remain valid because source and target both live in bin/.
        overlay.append(clone(source, target, target_data, next_ino))
        next_ino += 1
        private_targets[relative] = target
        records.append(
            {
                "kind": private_roles[relative],
                "source": relative,
                "target": target,
                "source_sha256": sha256(source.data),
                "target_sha256": sha256(target_data),
                "bytes": len(target_data),
                "needed": parsed.needed if parsed is not None else [],
                "source_interpreter": source_interpreter,
                "target_interpreter": target_interpreter,
                "exact_cstring_patches": exact_cstring_patches,
            }
        )

    # The shorter recovery alias is the target of the explicitly manifested
    # fixed-span C-string patch above.  It resolves back into the private bin/.
    recovery_alias = newc.regular_file(
        "system/tw/bin/r",
        b"recovery",
        mode=0o120777,
        ino=next_ino,
    )
    next_ino += 1
    overlay.append(recovery_alias)
    records.append(
        {
            "kind": "route_symlink",
            "source": None,
            "target": "system/tw/bin/r",
            "target_sha256": sha256(recovery_alias.data),
            "bytes": len(recovery_alias.data),
            "symlink_target": "recovery",
        }
    )

    if interpreters != {"/system/bin/linker64"}:
        raise SystemExit(f"dynamic private executables have inconsistent interpreters: {sorted(interpreters)}")
    linker_relative = next(iter(interpreters)).lstrip("/")
    linker = source_entries.get(linker_relative)
    if linker is None:
        raise SystemExit(f"dynamic linker is absent from cpio: {linker_relative}")
    ensure_tree_matches_archive(args.twrp_tree, linker_relative, linker)
    overlay.append(clone(linker, "system/tw/linker64", None, next_ino))
    next_ino += 1
    records.append(
        {
            "kind": "linker",
            "source": linker_relative,
            "target": "system/tw/linker64",
            "source_sha256": sha256(linker.data),
            "target_sha256": sha256(linker.data),
            "bytes": len(linker.data),
        }
    )

    # TWRP recovery uses absolute /system/bin helper paths.  Preserve every
    # existing H.40 binary, but add a shell trampoline when that path is absent.
    wrapper_records = []
    for relative in requested_helpers:
        if relative in stock_entries:
            wrapper_records.append(
                {
                    "source": relative,
                    "target": relative,
                    "private_target": private_targets[relative],
                    "routing": "stock_path_preserved",
                }
            )
            continue
        basename = PurePosixPath(relative).name
        data = wrapper_for(basename)
        wrapper = newc.regular_file(relative, data, mode=0o100755, ino=next_ino)
        next_ino += 1
        overlay.append(wrapper)
        record = {
            "kind": "wrapper",
            "source": relative,
            "target": relative,
            "private_target": private_targets[relative],
            "target_sha256": sha256(data),
            "bytes": len(data),
            "routing": "stock_shell_exec_private",
        }
        records.append(record)
        wrapper_records.append(record)

    asset_records = []
    for raw_relative in original_assets:
        relative = newc.normalize_name(raw_relative)
        source = source_entries.get(relative)
        if source is None:
            if relative in DEFAULT_ORIGINAL_ASSETS:
                continue
            raise SystemExit(f"requested TWRP original-path asset is absent from cpio: {relative}")
        if relative in stock_entries:
            raise SystemExit(f"refusing to overwrite stock path with a TWRP asset: {relative}")
        copied = clone(source, relative, None, next_ino)
        next_ino += 1
        overlay.append(copied)
        record = {
            "kind": "original_asset",
            "source": relative,
            "target": relative,
            "source_sha256": sha256(source.data),
            "target_sha256": sha256(source.data),
            "bytes": len(source.data),
        }
        records.append(record)
        asset_records.append(record)

    target_library_names = set()
    target_library_sources = {}
    for soname, (relative, _path, parsed) in sorted(selected.items(), key=lambda item: item[1][0]):
        source = source_entries.get(relative)
        if source is None:
            raise SystemExit(f"closure library is absent from cpio: {relative}")
        ensure_tree_matches_archive(args.twrp_tree, relative, source)
        basename = PurePosixPath(relative).name
        if basename in target_library_names:
            raise SystemExit(f"private library basename collision: {basename}")
        target_library_names.add(basename)
        target_library_sources[basename] = relative
        target = f"system/tw/lib64/{basename}"
        overlay.append(clone(source, target, None, next_ino))
        next_ino += 1
        records.append(
            {
                "kind": "library",
                "soname": soname,
                "requested_by": requested_by[soname],
                "source": relative,
                "target": target,
                "source_sha256": sha256(source.data),
                "target_sha256": sha256(source.data),
                "bytes": len(source.data),
                "needed": parsed.needed,
            }
        )

    resource_entries = [
        entry
        for entry in source_entries.values()
        if entry.name == "twres" or entry.name.startswith("twres/")
    ]
    if not resource_entries:
        raise SystemExit("TWRP ramdisk has no /twres resources")
    for source in sorted(resource_entries, key=lambda item: (item.name.count("/"), item.name)):
        overlay.append(clone(source, source.name, None, next_ino))
        next_ino += 1
        records.append(
            {
                "kind": "resource",
                "source": source.name,
                "target": source.name,
                "source_sha256": sha256(source.data),
                "target_sha256": sha256(source.data),
                "bytes": len(source.data),
            }
        )

    dlopen_manifest_section = None
    if dlopen is not None:
        resolution_records = []
        dependency_targets = set()

        # Add only TWRP-side dependencies that were not already selected for
        # recovery/helpers.  No unlisted stock file is ever considered here.
        for needed, row in sorted(dlopen["selected"].items(), key=lambda item: (item[1][2], item[0])):
            _priority, provenance, relative, _path, parsed, _stock_entry, _manifest_item = row
            basename = PurePosixPath(relative).name
            target = f"system/tw/lib64/{basename}"
            dependency_targets.add(target)
            if provenance == "twrp":
                source = source_entries.get(relative)
                if source is None:
                    raise SystemExit(f"H.40 closure TWRP library is absent from cpio: {relative}")
                ensure_tree_matches_archive(args.twrp_tree, relative, source)
                if basename in target_library_names:
                    existing_relative = target_library_sources[basename]
                    existing = source_entries[existing_relative]
                    if existing.data != source.data:
                        raise SystemExit(
                            f"H.40 closure collides with a different private TWRP library: {basename}"
                        )
                else:
                    target_library_names.add(basename)
                    target_library_sources[basename] = relative
                    overlay.append(clone(source, target, None, next_ino))
                    next_ino += 1
                    records.append(
                        {
                            "kind": "library",
                            "closure_role": "dlopen_dependency",
                            "soname": parsed.soname or needed,
                            "requested_by": dlopen["requested_by"][needed],
                            "source": relative,
                            "target": target,
                            "source_sha256": sha256(source.data),
                            "target_sha256": sha256(source.data),
                            "bytes": len(source.data),
                            "needed": parsed.needed,
                        }
                    )
            resolution_records.append(
                {
                    "needed": needed,
                    "requested_by": dlopen["requested_by"][needed],
                    "provenance": provenance,
                    "source": relative,
                    "target": target,
                }
            )

        proprietary_records = []
        for item in dlopen["manifest"].files:
            relative, _path, parsed, source, _manifest_item = dlopen["proprietary"][item.name]
            basename = item.name
            if basename in target_library_names:
                raise SystemExit(
                    f"pinned H.40 blob would replace a TWRP private-runtime library: {basename}"
                )
            target_library_names.add(basename)
            target_library_sources[basename] = relative
            target = item.target
            overlay.append(clone(source, target, None, next_ino))
            next_ino += 1
            kind = "dlopen_root" if basename == h40_dlopen.ROOT_LIBRARY else "dlopen_dependency"
            record = {
                "kind": kind,
                "soname": parsed.soname,
                "source": relative,
                "target": target,
                "source_sha256": item.sha256,
                "target_sha256": item.sha256,
                "bytes": item.bytes,
                "needed": parsed.needed,
                "provenance": "stock_cpio_hash_pinned",
            }
            records.append(record)
            proprietary_records.append(record)

        root_target = f"system/tw/lib64/{h40_dlopen.ROOT_LIBRARY}"
        expected_proprietary_targets = {
            f"system/tw/lib64/{name}" for name in h40_dlopen.EXPECTED_FILES
        }
        actual_proprietary_targets = {record["target"] for record in proprietary_records}
        if actual_proprietary_targets != expected_proprietary_targets:
            raise SystemExit("internal error: incomplete H.40 proprietary target set")
        dlopen_manifest_section = {
            "format": 1,
            "manifest_sha256": dlopen["manifest"].raw_sha256,
            "source_rom": dlopen["manifest"].document["source"]["rom"],
            "source_boot_sha256": dlopen["manifest"].document["source"]["boot_sha256"],
            "destination_directory": h40_dlopen.DESTINATION_DIRECTORY,
            "root_target": root_target,
            "required_root_symbols": list(h40_dlopen.REQUIRED_ROOT_SYMBOLS),
            "proprietary_targets": sorted(actual_proprietary_targets),
            "dependency_targets": sorted(dependency_targets),
            "load_group_targets": sorted({root_target} | dependency_targets),
            "needed_resolution": sorted(resolution_records, key=lambda row: row["needed"]),
            "dt_needed_closure_count": len(dlopen["selected"]),
            "unresolved_strong_symbol_groups": len(dlopen["unresolved"]),
        }

    names = [entry.name for entry in overlay]
    if len(names) != len(set(names)):
        duplicates = sorted(name for name in set(names) if names.count(name) > 1)
        raise SystemExit(f"duplicate overlay targets: {duplicates}")
    newc.write(args.output, overlay)

    # Parse the result again before declaring success.
    roundtrip = newc.index(newc.read(args.output))
    for entry in overlay:
        actual = roundtrip.get(entry.name)
        if actual != entry:
            raise SystemExit(f"overlay round-trip mismatch for {entry.name}")

    manifest = {
        "format": 1,
        "twrp_cpio_sha256": sha256(args.twrp_cpio.read_bytes()),
        "stock_cpio_sha256": sha256(args.stock_cpio.read_bytes()),
        "private_interpreter": PRIVATE_INTERPRETER,
        "entry_points": entry_points,
        "required_helpers": [newc.normalize_name(item) for item in required_helpers],
        "optional_helpers_included": [
            newc.normalize_name(item)
            for item in optional_helpers
            if newc.normalize_name(item) in source_entries
        ],
        "private_executable_sources": private_sources,
        "helper_routes": wrapper_records,
        "original_assets_included": [record["target"] for record in asset_records],
        "library_count": sum(
            record["kind"] in {"library", "dlopen_root", "dlopen_dependency"}
            for record in records
        ),
        "resource_entry_count": len(resource_entries),
        "overlay_entry_count": len(overlay),
        "overlay_bytes": args.output.stat().st_size,
        "overlay_sha256": sha256(args.output.read_bytes()),
        "records": records,
    }
    if dlopen_manifest_section is not None:
        manifest["dlopen_root"] = dlopen_manifest_section
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "libraries": manifest["library_count"],
                "private_executables": len(private_sources),
                "wrappers": sum(record["routing"] == "stock_shell_exec_private" for record in wrapper_records),
                "resources": len(resource_entries),
                "bytes": args.output.stat().st_size,
                "sha256": manifest["overlay_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
