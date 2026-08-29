#!/usr/bin/env python3
"""Apply the reviewed RC2 recovery fixes directly to a raw newc ramdisk."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import newc


REQUIRED_STAGE_INPUTS = (
    "system/etc/init/init.rc",
    "init.recovery.qcom.rc",
    "etc/recovery.fstab",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--fixer", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    stage = args.work_dir / "stage"
    if stage.exists():
        raise SystemExit(f"stage already exists: {stage}")
    stage.mkdir()

    source_entries = newc.read(args.input)
    source_index = newc.index(source_entries)
    if len(source_entries) != len(source_index):
        raise SystemExit("source ramdisk contains duplicate paths")
    for target in REQUIRED_STAGE_INPUTS:
        entry = source_index.get(target)
        if entry is None or entry.mode & 0o170000 != 0o100000:
            raise SystemExit(f"source ramdisk lacks regular file: {target}")
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(entry.data)

    fix_report = args.work_dir / "fix-report.json"
    subprocess.run(
        [sys.executable, str(args.fixer), str(stage), "--report", str(fix_report)],
        check=True,
    )
    fix_facts = json.loads(fix_report.read_text(encoding="utf-8"))
    targets = set(fix_facts["patched_files"])
    targets.update(fix_facts["copied_payloads"])
    copied_payload_modes = fix_facts.get("copied_payload_modes", {})
    if not set(copied_payload_modes) <= set(fix_facts["copied_payloads"]):
        raise SystemExit("copy-mode declaration refers to a non-payload target")
    for target, mode in copied_payload_modes.items():
        if not isinstance(mode, int) or mode & 0o170000 != 0o100000:
            raise SystemExit(f"invalid copied payload mode for {target}: {mode!r}")
        if target in source_index and source_index[target].mode != mode:
            raise SystemExit(f"copy-mode declaration would change stock metadata: {target}")
    replacements = {}
    for target in sorted(targets):
        path = stage / target
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"fix transformer did not materialize: {target}")
        replacements[target] = path.read_bytes()

    output_entries = []
    changed = {}
    remaining = dict(replacements)
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
        mode = copied_payload_modes.get(target, 0o100644)
        output_entries.append(
            newc.regular_file(target, data, mode=mode, ino=next_ino)
        )
        added[target] = {"bytes": len(data), "sha256": sha256(data), "mode": mode}
        next_ino += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    newc.write(args.output, output_entries)
    final_entries = newc.read(args.output)
    final_index = newc.index(final_entries)
    if len(final_entries) != len(final_index):
        raise SystemExit("fixed ramdisk contains duplicate paths")
    for before in source_entries:
        after = final_index.get(before.name)
        if after is None:
            raise SystemExit(f"source entry disappeared: {before.name}")
        if before.name in changed:
            if metadata(before) != metadata(after):
                raise SystemExit(f"metadata changed for replacement: {before.name}")
        elif before != after:
            raise SystemExit(f"unapproved source entry changed: {before.name}")
    for target, data in replacements.items():
        if final_index[target].data != data:
            raise SystemExit(f"final recovery-fix payload mismatch: {target}")
    for target, mode in copied_payload_modes.items():
        if final_index[target].mode != mode:
            raise SystemExit(f"final recovery-fix payload mode mismatch: {target}")

    report = {
        "format": 1,
        "name": "guacamole-h40-rc2-recovery-fixes-cpio",
        "source_entries": len(source_entries),
        "final_entries": len(final_entries),
        "source_sha256": sha256(args.input.read_bytes()),
        "output_sha256": sha256(args.output.read_bytes()),
        "changed": changed,
        "added": added,
        "fix_report": fix_facts,
        "checks": {
            "unrelated_entries_preserved": True,
            "replacement_metadata_preserved": True,
            "no_duplicate_paths": True,
            "all_reviewed_fixes_installed": True,
            "copied_payload_modes_preserved": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
