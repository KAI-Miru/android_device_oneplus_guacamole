#!/usr/bin/env python3
"""Generate TWRP's self-repacking manifests for a final newc ramdisk.

``Flash Current TWRP`` verifies the installed ramdisk with
``/ramdisk-files.sha256sum`` and rebuilds it from ``/ramdisk-files.txt``.
Those files must therefore describe the completed stock-first ramdisk, not the
compiled TWRP input from which only selected files were copied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import newc


FILE_LIST = "ramdisk-files.txt"
HASH_LIST = "ramdisk-files.sha256sum"
MANIFESTS = frozenset((FILE_LIST, HASH_LIST))
REGULAR_FILE = 0o100000


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _listed(name: str) -> bool:
    # Match TeamWin's build-time `sed "/lib\/modules\//d"` rule exactly:
    # retain the modules directory itself, but omit its children.
    return "lib/modules/" not in name


def _hashed(entry: newc.Entry) -> bool:
    # Match TeamWin's `find -type f` plus its two exclusion expressions.
    return (
        entry.mode & 0o170000 == REGULAR_FILE
        and entry.name != HASH_LIST
        and "lib/modules" not in entry.name
        and "prop.default" not in entry.name
    )


def build_repackable_entries(entries: list[newc.Entry]) -> tuple[list[newc.Entry], dict]:
    base = [entry for entry in entries if entry.name not in MANIFESTS]
    names = [entry.name for entry in base]
    if len(names) != len(set(names)):
        raise SystemExit("input CPIO contains duplicate paths")

    next_ino = max((entry.ino for entry in base), default=0) + 1
    output_names = names + [HASH_LIST, FILE_LIST]
    file_list_data = (".\n" + "".join(f"{name}\n" for name in output_names if _listed(name))).encode()
    file_list_entry = newc.regular_file(FILE_LIST, file_list_data, ino=next_ino + 1)

    hash_sources = base + [file_list_entry]
    hash_list_data = "".join(
        f"{sha256(entry.data)}  ./{entry.name}\n"
        for entry in hash_sources
        if _hashed(entry)
    ).encode()
    hash_list_entry = newc.regular_file(HASH_LIST, hash_list_data, ino=next_ino)
    output = base + [hash_list_entry, file_list_entry]

    report = {
        "format": 1,
        "result": "PASS",
        "input_entries": len(entries),
        "output_entries": len(output),
        "file_list": {
            "path": FILE_LIST,
            "lines": file_list_data.count(b"\n"),
            "bytes": len(file_list_data),
            "sha256": sha256(file_list_data),
        },
        "hash_list": {
            "path": HASH_LIST,
            "lines": hash_list_data.count(b"\n"),
            "bytes": len(hash_list_data),
            "sha256": sha256(hash_list_data),
        },
    }
    return output, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    output, report = build_repackable_entries(newc.read(args.input))
    newc.write(args.output, output)
    report["output_bytes"] = args.output.stat().st_size
    report["output_sha256"] = sha256(args.output.read_bytes())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
