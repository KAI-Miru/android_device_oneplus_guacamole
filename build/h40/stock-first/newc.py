#!/usr/bin/env python3
"""Minimal, deterministic reader/writer for Linux ``newc`` CPIO archives.

The implementation intentionally has no third-party dependencies.  It keeps all
metadata needed by an Android ramdisk and treats symlink targets as ordinary entry
payloads, so it does not depend on host filesystem symlink support.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable


HEADER_BYTES = 110
TRAILER = "TRAILER!!!"


class NewcError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    devmajor: int
    devminor: int
    rdevmajor: int
    rdevminor: int
    data: bytes

    def with_name_and_data(self, name: str, data: bytes | None = None) -> "Entry":
        return replace(self, name=name, data=self.data if data is None else data)


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def normalize_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def read(path: str | Path) -> list[Entry]:
    source = Path(path)
    blob = source.read_bytes()
    entries: list[Entry] = []
    offset = 0
    saw_trailer = False

    while offset + HEADER_BYTES <= len(blob):
        magic = blob[offset : offset + 6]
        if magic not in (b"070701", b"070702"):
            if all(byte == 0 for byte in blob[offset:]):
                break
            raise NewcError(f"invalid newc magic {magic!r} at {offset:#x} in {source}")

        fields = []
        cursor = offset + 6
        for _ in range(13):
            raw = blob[cursor : cursor + 8]
            try:
                fields.append(int(raw, 16))
            except ValueError as exc:
                raise NewcError(f"invalid newc field {raw!r} at {cursor:#x} in {source}") from exc
            cursor += 8

        (
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            filesize,
            devmajor,
            devminor,
            rdevmajor,
            rdevminor,
            namesize,
            _check,
        ) = fields
        if namesize < 1:
            raise NewcError(f"zero-length name at {offset:#x} in {source}")

        name_start = offset + HEADER_BYTES
        name_end = name_start + namesize
        data_start = align(name_end, 4)
        data_end = data_start + filesize
        next_offset = align(data_end, 4)
        if next_offset > len(blob):
            raise NewcError(f"truncated entry at {offset:#x} in {source}")
        if blob[name_end - 1] != 0:
            raise NewcError(f"unterminated entry name at {offset:#x} in {source}")
        try:
            name = blob[name_start : name_end - 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NewcError(f"non-UTF-8 entry name at {offset:#x} in {source}") from exc
        if name == TRAILER:
            saw_trailer = True
            offset = next_offset
            break

        entries.append(
            Entry(
                name=normalize_name(name),
                ino=ino,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                devmajor=devmajor,
                devminor=devminor,
                rdevmajor=rdevmajor,
                rdevminor=rdevminor,
                data=blob[data_start:data_end],
            )
        )
        offset = next_offset

    if not saw_trailer:
        raise NewcError(f"missing {TRAILER} entry in {source}")
    if any(byte != 0 for byte in blob[offset:]):
        raise NewcError(f"non-zero bytes follow the trailer in {source}")
    return entries


def index(entries: Iterable[Entry]) -> dict[str, Entry]:
    """Return the last occurrence of every normalized archive path."""

    result: dict[str, Entry] = {}
    for entry in entries:
        result[normalize_name(entry.name)] = entry
    return result


def _header(entry: Entry, name_size: int, file_size: int) -> bytes:
    values = (
        entry.ino,
        entry.mode,
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.mtime,
        file_size,
        entry.devmajor,
        entry.devminor,
        entry.rdevmajor,
        entry.rdevminor,
        name_size,
        0,
    )
    for value in values:
        if not 0 <= value <= 0xFFFFFFFF:
            raise NewcError(f"newc field out of range for {entry.name!r}: {value}")
    return b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in values)


def _append_entry(buffer: bytearray, entry: Entry) -> None:
    name = normalize_name(entry.name)
    if not name or "\x00" in name:
        raise NewcError(f"invalid entry name {entry.name!r}")
    name_bytes = name.encode("utf-8") + b"\0"
    buffer.extend(_header(entry, len(name_bytes), len(entry.data)))
    buffer.extend(name_bytes)
    buffer.extend(b"\0" * (align(len(buffer), 4) - len(buffer)))
    buffer.extend(entry.data)
    buffer.extend(b"\0" * (align(len(buffer), 4) - len(buffer)))


def write(path: str | Path, entries: Iterable[Entry], archive_alignment: int = 256) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    buffer = bytearray()
    seen: set[str] = set()
    for raw_entry in entries:
        name = normalize_name(raw_entry.name)
        if name == TRAILER:
            raise NewcError(f"caller supplied reserved entry {TRAILER!r}")
        if name in seen:
            raise NewcError(f"duplicate output entry {name!r}")
        seen.add(name)
        _append_entry(buffer, replace(raw_entry, name=name))

    trailer = Entry(
        name=TRAILER,
        ino=0,
        mode=0,
        uid=0,
        gid=0,
        nlink=1,
        mtime=0,
        devmajor=0,
        devminor=0,
        rdevmajor=0,
        rdevminor=0,
        data=b"",
    )
    _append_entry(buffer, trailer)
    buffer.extend(b"\0" * (align(len(buffer), archive_alignment) - len(buffer)))
    destination.write_bytes(buffer)


def regular_file(name: str, data: bytes, mode: int = 0o100644, ino: int = 1) -> Entry:
    return Entry(
        name=normalize_name(name),
        ino=ino,
        mode=mode,
        uid=0,
        gid=0,
        nlink=1,
        mtime=0,
        devmajor=0,
        devminor=0,
        rdevmajor=0,
        rdevminor=0,
        data=data,
    )


def directory(name: str, mode: int = 0o040755, ino: int = 1) -> Entry:
    return regular_file(name, b"", mode=mode, ino=ino)
