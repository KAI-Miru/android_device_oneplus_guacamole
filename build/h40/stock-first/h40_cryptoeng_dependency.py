#!/usr/bin/env python3
"""Build the pinned H.40 stock-service dependency overlay.

The stock recovery ramdisk contains ColorOS' cryptoeng service but omits one of
that service's hard ``DT_NEEDED`` libraries. The tested Guacamole RC2 library
is the H.40 system_ext interface library, not the different H.40 ODM/Hotdog
variant. Callers must provide the checked-in, hash-pinned file explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import ModuleType

import newc


EXPECTED_ROM = "OnePlus 7 Pro ColorOS 12.1 H.40"
SOURCE_RELATIVE = "system/system/system_ext/lib64/vendor.oplus.hardware.commondcs@1.0.so"
TARGET = "system/lib64/vendor.oplus.hardware.commondcs@1.0.so"
SONAME = "vendor.oplus.hardware.commondcs@1.0.so"
SOURCE_BYTES = 75_024
SOURCE_SHA256 = "e9ea4b62cd235b095a9da141276cf30add2c20acb73c6aa2cfd7bc0c9d6cc464"

SERVICE = "system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service"
SERVICE_BYTES = 69_424
SERVICE_SHA256 = "18f4eacc1a4fcd3fe125abb544c7742041f89de2802f041ee1b88da6c93fe79e"
SERVICE_REQUIRED_SYMBOL = (
    "_ZN6vendor5oplus8hardware9commondcs4V1_020ICommonDcsHalService10getService"
    "ERKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEEb"
)

LINKER_CONFIG = "system/etc/ld.config.txt"
LINKER_SEARCH = "namespace.default.search.paths = /system/${LIB}"
INIT_RC = "system/etc/init/init.rc"
TEMPLATE = "system/lib64/vendor.oplus.hardware.cryptoeng@1.0.so"
OVERLAY_INO = 740_000


class DependencyError(ValueError):
    """The explicit H.40 dependency input is absent or does not match H.40."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DependencyError(message)


def load_elf_audit(directory: Path) -> ModuleType:
    source = directory / "elf_audit.py"
    require(source.is_file(), f"ELF auditor is absent: {source}")
    spec = importlib.util.spec_from_file_location("h40_cryptoeng_elf_audit", source)
    require(spec is not None and spec.loader is not None, f"cannot load ELF auditor: {source}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _regular(entry: newc.Entry, name: str) -> None:
    require(entry.mode & 0o170000 == 0o100000, f"expected a regular file: {name}")
    require(entry.data[:4] == b"\x7fELF", f"expected an ELF file: {name}")


def _entry(entries: dict[str, newc.Entry], name: str) -> newc.Entry:
    entry = entries.get(name)
    require(entry is not None, f"stock CPIO is missing {name}")
    return entry


def _normalize_link(path: PurePosixPath, target: str) -> str:
    raw = PurePosixPath(target.lstrip("/")) if target.startswith("/") else path.parent / target
    parts: list[str] = []
    for part in raw.parts:
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(parts), f"unsafe stock symlink target: {path} -> {target}")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def _resolve_stock_library(entries: dict[str, newc.Entry], needed: str) -> tuple[str, newc.Entry]:
    require("/" not in needed and "\\" not in needed, f"unsafe DT_NEEDED name: {needed!r}")
    name = f"system/lib64/{needed}"
    seen: set[str] = set()
    for _ in range(16):
        require(name not in seen, f"stock library symlink cycle at {name}")
        seen.add(name)
        entry = _entry(entries, name)
        file_type = entry.mode & 0o170000
        if file_type == 0o100000:
            _regular(entry, name)
            return name, entry
        require(file_type == 0o120000, f"stock dependency is not a file or symlink: {name}")
        try:
            target = entry.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyError(f"non-UTF-8 stock symlink target: {name}") from exc
        name = _normalize_link(PurePosixPath(name), target)
        require(name.startswith("system/lib64/"), f"stock dependency escaped /system/lib64: {name}")
    raise DependencyError(f"too many stock symlink hops for {needed}")


def _parse_elf(module: ModuleType, path: Path, label: str):
    try:
        return module.Elf(path)
    except Exception as exc:
        raise DependencyError(f"cannot parse {label} as ELF: {exc}") from exc


def _parse_entry(module: ModuleType, entry: newc.Entry, label: str, temp: Path):
    path = temp / f"{sha256(entry.data)}.elf"
    if not path.exists():
        path.write_bytes(entry.data)
    return _parse_elf(module, path, label)


def _text(entry: newc.Entry, name: str) -> str:
    try:
        return entry.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyError(f"non-UTF-8 stock text file: {name}") from exc


def _action_commands(text: str, header: str) -> list[str]:
    lines = text.splitlines()
    matches = [index for index, line in enumerate(lines) if line.strip() == header]
    require(len(matches) == 1, f"stock init must contain exactly one {header!r} action")
    commands: list[str] = []
    for line in lines[matches[0] + 1 :]:
        if line and not line[0].isspace():
            break
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            commands.append(stripped)
    return commands


def _stock_contract(stock_entries: dict[str, newc.Entry]) -> newc.Entry:
    require(TARGET not in stock_entries, f"stock CPIO already contains {TARGET}; overlay is unnecessary")

    service_entry = _entry(stock_entries, SERVICE)
    _regular(service_entry, SERVICE)
    require(len(service_entry.data) == SERVICE_BYTES, f"unexpected H.40 cryptoeng service size: {SERVICE}")
    require(sha256(service_entry.data) == SERVICE_SHA256, f"unexpected H.40 cryptoeng service hash: {SERVICE}")

    linker_config = _text(_entry(stock_entries, LINKER_CONFIG), LINKER_CONFIG)
    require(linker_config.count("[recovery]") == 1, "stock linker config lacks one recovery namespace")
    require(linker_config.count(LINKER_SEARCH) == 1, "stock recovery does not search exactly /system/${LIB}")

    init_rc = _text(_entry(stock_entries, INIT_RC), INIT_RC)
    service_headers = (
        "service qseecomd /system/bin/qseecomd",
        "service keymaster-4-0 /system/bin/android.hardware.keymaster@4.0-service-qti",
        "service hwservicemanager /system/bin/hwservicemanager",
        f"service hal_cryptoeng_oplus /{SERVICE}",
    )
    for header in service_headers:
        require(init_rc.count(header) == 1, f"stock init service contract changed: {header}")
    require("service common_dcs " not in init_rc, "stock recovery unexpectedly declares a CommonDCS daemon")
    require(
        _action_commands(init_rc, "on property:enable.qseecomd.service=1")
        == [
            "wait /dev/block/bootdevice/by-name/modem",
            "start hwservicemanager",
            "start keymaster-4-0",
            "start qseecomd",
        ],
        "stock trusted-service startup order changed",
    )
    require(
        "start hal_cryptoeng_oplus" in _action_commands(init_rc, "on fs"),
        "stock init no longer starts cryptoeng during fs",
    )
    return service_entry


def _validate_elf_contract(
    stock_entries: dict[str, newc.Entry],
    service_entry: newc.Entry,
    source_elf,
    elf_audit: ModuleType,
    temp: Path,
) -> tuple[dict[str, tuple[str, object]], list[dict[str, str]]]:
    service_elf = _parse_entry(elf_audit, service_entry, SERVICE, temp)
    require(service_elf.bits == 64 and service_elf.e_machine == 183, "cryptoeng is not AArch64 ELF64")
    require(source_elf.bits == 64 and source_elf.e_machine == 183, "CommonDCS is not AArch64 ELF64")
    require(source_elf.soname == SONAME, f"unexpected CommonDCS SONAME: {source_elf.soname!r}")
    require(SONAME in service_elf.needed, "cryptoeng no longer DT_NEEDED-links CommonDCS")
    require(
        SERVICE_REQUIRED_SYMBOL in service_elf.undefined_strong,
        "cryptoeng no longer imports the pinned CommonDCS getService symbol",
    )
    require(
        SERVICE_REQUIRED_SYMBOL in source_elf.defined,
        "H.40 system_ext CommonDCS library does not export cryptoeng's getService symbol",
    )

    # Resolve the complete recursive DT_NEEDED graph under the recovery
    # namespace.  The injected library is the only allowed non-stock node.
    parsed: dict[str, tuple[str, object]] = {SONAME: (TARGET, source_elf)}
    queue: list[tuple[str, object]] = [(SERVICE, service_elf), (TARGET, source_elf)]
    edges: list[dict[str, str]] = []
    while queue:
        requester, elf = queue.pop(0)
        for needed in elf.needed:
            resolved = parsed.get(needed)
            if resolved is None:
                resolved_path, dependency_entry = _resolve_stock_library(stock_entries, needed)
                dependency_elf = _parse_entry(elf_audit, dependency_entry, resolved_path, temp)
                require(
                    dependency_elf.soname in (None, needed),
                    f"stock dependency SONAME mismatch: {needed} -> {dependency_elf.soname!r}",
                )
                resolved = (resolved_path, dependency_elf)
                parsed[needed] = resolved
                queue.append(resolved)
            edges.append({"from": requester, "needed": needed, "resolved": resolved[0]})
    return parsed, edges


def _facts(source_data: bytes, service_entry: newc.Entry, parsed: dict, edges: list[dict]) -> dict:
    return {
        "rom": EXPECTED_ROM,
        "source": SOURCE_RELATIVE,
        "source_bytes": len(source_data),
        "source_sha256": sha256(source_data),
        "target": TARGET,
        "soname": SONAME,
        "service": SERVICE,
        "service_sha256": sha256(service_entry.data),
        "linker_search": "/system/${LIB}",
        "closure_library_count": len(parsed),
        "closure_edge_count": len(edges),
        "closure": sorted(edges, key=lambda row: (row["from"], row["needed"], row["resolved"])),
    }


def validate(
    stock_entries: dict[str, newc.Entry], source: Path, elf_audit: ModuleType
) -> tuple[bytes, dict]:
    """Validate the exact service/library pair and its stock linker closure."""

    service_entry = _stock_contract(stock_entries)

    require(source.is_file(), f"H.40 system_ext CommonDCS library is absent: {source}")
    source_data = source.read_bytes()
    require(len(source_data) == SOURCE_BYTES, f"H.40 system_ext CommonDCS library has wrong size: {source}")
    require(sha256(source_data) == SOURCE_SHA256, f"H.40 system_ext CommonDCS library hash mismatch: {source}")

    with tempfile.TemporaryDirectory(prefix="h40-cryptoeng-elf-") as raw_temp:
        temp = Path(raw_temp)
        source_elf = _parse_elf(elf_audit, source, SOURCE_RELATIVE)
        parsed, edges = _validate_elf_contract(
            stock_entries, service_entry, source_elf, elf_audit, temp
        )
    return source_data, _facts(source_data, service_entry, parsed, edges)


def load_manifest(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyError(f"invalid H.40 cryptoeng manifest {path}: {exc}") from exc
    required_keys = {
        "rom",
        "source",
        "source_bytes",
        "source_sha256",
        "target",
        "soname",
        "service",
        "service_sha256",
        "linker_search",
        "closure_library_count",
        "closure_edge_count",
        "closure",
        "overlay_sha256",
        "overlay_entries",
    }
    require(isinstance(document, dict) and set(document) == required_keys, "bad H.40 cryptoeng manifest schema")
    require(document["rom"] == EXPECTED_ROM, "bad H.40 cryptoeng manifest ROM")
    require(document["source"] == SOURCE_RELATIVE, "bad H.40 cryptoeng manifest source")
    require(document["source_bytes"] == SOURCE_BYTES, "bad H.40 cryptoeng manifest byte count")
    require(document["source_sha256"] == SOURCE_SHA256, "bad H.40 cryptoeng manifest source hash")
    require(document["target"] == TARGET, "bad H.40 cryptoeng manifest target")
    require(document["soname"] == SONAME, "bad H.40 cryptoeng manifest SONAME")
    require(document["service"] == SERVICE, "bad H.40 cryptoeng manifest service")
    require(document["service_sha256"] == SERVICE_SHA256, "bad H.40 cryptoeng manifest service hash")
    require(document["linker_search"] == "/system/${LIB}", "bad H.40 cryptoeng linker search")
    require(document["overlay_entries"] == [TARGET], "bad H.40 cryptoeng overlay entry set")
    require(
        isinstance(document["overlay_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["overlay_sha256"]) is not None,
        "bad H.40 cryptoeng overlay hash",
    )
    closure = document["closure"]
    require(isinstance(closure, list), "bad H.40 cryptoeng closure")
    require(document["closure_edge_count"] == len(closure), "bad H.40 cryptoeng edge count")
    require(
        isinstance(document["closure_library_count"], int)
        and not isinstance(document["closure_library_count"], bool)
        and document["closure_library_count"] > 0,
        "bad H.40 cryptoeng library count",
    )
    for edge in closure:
        require(
            isinstance(edge, dict)
            and set(edge) == {"from", "needed", "resolved"}
            and all(isinstance(value, str) and value for value in edge.values()),
            "bad H.40 cryptoeng closure edge",
        )
    require(
        closure == sorted(closure, key=lambda row: (row["from"], row["needed"], row["resolved"])),
        "H.40 cryptoeng closure is not deterministic",
    )
    return document, sha256(raw)


def validate_final(
    stock_entries: dict[str, newc.Entry],
    final_entries: dict[str, newc.Entry],
    manifest: dict,
    elf_audit: ModuleType,
) -> dict:
    """Independently revalidate the injected final entry and its load graph."""

    service_entry = _stock_contract(stock_entries)
    require(final_entries.get(SERVICE) == service_entry, "final cryptoeng service differs from stock H.40")
    target_entry = _entry(final_entries, TARGET)
    _regular(target_entry, TARGET)
    require(len(target_entry.data) == SOURCE_BYTES, "final CommonDCS library has wrong size")
    require(sha256(target_entry.data) == SOURCE_SHA256, "final CommonDCS library hash mismatch")

    template = _entry(stock_entries, TEMPLATE)
    _regular(template, TEMPLATE)
    require(target_entry.ino == OVERLAY_INO, "final CommonDCS overlay inode changed")
    require(
        (
            target_entry.mode,
            target_entry.uid,
            target_entry.gid,
            target_entry.nlink,
            target_entry.mtime,
            target_entry.devmajor,
            target_entry.devminor,
            target_entry.rdevmajor,
            target_entry.rdevminor,
        )
        == (
            template.mode,
            template.uid,
            template.gid,
            1,
            template.mtime,
            template.devmajor,
            template.devminor,
            template.rdevmajor,
            template.rdevminor,
        ),
        "final CommonDCS metadata was not cloned from the stock system library template",
    )

    with tempfile.TemporaryDirectory(prefix="h40-cryptoeng-final-elf-") as raw_temp:
        temp = Path(raw_temp)
        source_elf = _parse_entry(elf_audit, target_entry, TARGET, temp)
        parsed, edges = _validate_elf_contract(
            stock_entries, service_entry, source_elf, elf_audit, temp
        )
    facts = _facts(target_entry.data, service_entry, parsed, edges)
    for key, value in facts.items():
        require(manifest.get(key) == value, f"H.40 cryptoeng manifest differs from final {key}")
    return facts


def build(
    stock_cpio: Path,
    source: Path,
    elf_audit_dir: Path,
    output: Path,
    manifest: Path,
) -> dict:
    stock_entries = newc.index(newc.read(stock_cpio))
    elf_audit = load_elf_audit(elf_audit_dir)
    source_data, facts = validate(stock_entries, source, elf_audit)

    template = _entry(stock_entries, TEMPLATE)
    _regular(template, TEMPLATE)
    overlay_entry = replace(
        template,
        name=TARGET,
        ino=OVERLAY_INO,
        nlink=1,
        data=source_data,
    )
    newc.write(output, [overlay_entry])
    facts["overlay_sha256"] = sha256(output.read_bytes())
    facts["overlay_entries"] = [TARGET]
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return facts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--elf-audit-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    facts = build(
        args.stock_cpio,
        args.source,
        args.elf_audit_dir,
        args.output,
        args.manifest,
    )
    print(
        f"wrote {args.output}: {facts['source_bytes']} bytes, "
        f"{facts['closure_library_count']} closure libraries"
    )


if __name__ == "__main__":
    main()
