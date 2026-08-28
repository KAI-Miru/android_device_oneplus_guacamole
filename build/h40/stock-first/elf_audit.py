#!/usr/bin/env python3
"""Small dependency/symbol auditor for Android ELF files.

This intentionally has no third-party dependencies so it can run in the
restricted Windows workspace.  It reads only the ELF program/section tables.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path


DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
PT_LOAD = 1
PT_DYNAMIC = 2
SHT_DYNSYM = 11
SHN_UNDEF = 0


class ElfError(Exception):
    pass


class Elf:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ElfError("not ELF")
        cls, enc = self.data[4], self.data[5]
        if cls not in (1, 2) or enc not in (1, 2):
            raise ElfError("unsupported class/encoding")
        self.bits = 32 if cls == 1 else 64
        self.endian = "<" if enc == 1 else ">"
        self._parse_header()
        self._parse_program_headers()
        self._parse_sections()
        self._parse_dynamic()
        self._parse_dynsym()

    def _unpack(self, fmt: str, off: int):
        size = struct.calcsize(self.endian + fmt)
        if off < 0 or off + size > len(self.data):
            raise ElfError(f"out of range at {off:#x}")
        return struct.unpack_from(self.endian + fmt, self.data, off)

    def _parse_header(self):
        if self.bits == 64:
            vals = self._unpack("HHIQQQIHHHHHH", 16)
        else:
            vals = self._unpack("HHIIIIIHHHHHH", 16)
        (
            self.e_type,
            self.e_machine,
            _version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            _flags,
            _ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = vals

    def _parse_program_headers(self):
        self.phdrs = []
        self.interpreter = None
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.bits == 64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = self._unpack(
                    "IIQQQQQQ", off
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = self._unpack(
                    "IIIIIIII", off
                )
            ph = {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "align": p_align,
            }
            self.phdrs.append(ph)
            if p_type == 3:  # PT_INTERP
                raw = self.data[p_offset : p_offset + p_filesz]
                self.interpreter = raw.split(b"\0", 1)[0].decode("utf-8", "replace")

    def vaddr_to_offset(self, addr: int) -> int:
        for ph in self.phdrs:
            if ph["type"] != PT_LOAD:
                continue
            start, end = ph["vaddr"], ph["vaddr"] + ph["filesz"]
            if start <= addr < end:
                return ph["offset"] + (addr - start)
        raise ElfError(f"virtual address {addr:#x} not file-backed")

    def _parse_sections(self):
        self.sections = []
        if not self.e_shoff or not self.e_shnum:
            return
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.bits == 64:
                vals = self._unpack("IIQQQQIIQQ", off)
            else:
                vals = self._unpack("IIIIIIIIII", off)
            raw.append(vals)
        shstr = b""
        if 0 <= self.e_shstrndx < len(raw):
            sh = raw[self.e_shstrndx]
            shstr = self.data[sh[4] : sh[4] + sh[5]]

        def cstr(blob: bytes, off: int) -> str:
            if off < 0 or off >= len(blob):
                return ""
            return blob[off : blob.find(b"\0", off) if b"\0" in blob[off:] else len(blob)].decode(
                "utf-8", "replace"
            )

        for vals in raw:
            name, typ, flags, addr, off, size, link, info, align, entsize = vals
            self.sections.append(
                {
                    "name": cstr(shstr, name),
                    "type": typ,
                    "flags": flags,
                    "addr": addr,
                    "offset": off,
                    "size": size,
                    "link": link,
                    "info": info,
                    "align": align,
                    "entsize": entsize,
                }
            )

    @staticmethod
    def _cstr(blob: bytes, off: int) -> str:
        if off < 0 or off >= len(blob):
            return ""
        end = blob.find(b"\0", off)
        if end < 0:
            end = len(blob)
        return blob[off:end].decode("utf-8", "replace")

    def _parse_dynamic(self):
        entries = []
        for ph in self.phdrs:
            if ph["type"] != PT_DYNAMIC:
                continue
            entsize = 16 if self.bits == 64 else 8
            fmt = "qQ" if self.bits == 64 else "iI"
            for off in range(ph["offset"], ph["offset"] + ph["filesz"], entsize):
                tag, val = self._unpack(fmt, off)
                if tag == DT_NULL:
                    break
                entries.append((tag, val))
        self.dynamic_entries = entries
        vals_by_tag = {}
        for tag, val in entries:
            vals_by_tag.setdefault(tag, []).append(val)
        strtab_addr = vals_by_tag.get(DT_STRTAB, [None])[0]
        strsz = vals_by_tag.get(DT_STRSZ, [0])[0]
        dynstr = b""
        if strtab_addr is not None:
            off = self.vaddr_to_offset(strtab_addr)
            dynstr = self.data[off : off + strsz]
        self.needed = [self._cstr(dynstr, x) for x in vals_by_tag.get(DT_NEEDED, [])]
        self.soname = self._cstr(dynstr, vals_by_tag[DT_SONAME][0]) if DT_SONAME in vals_by_tag else None
        self.rpath = self._cstr(dynstr, vals_by_tag[DT_RPATH][0]) if DT_RPATH in vals_by_tag else None
        self.runpath = self._cstr(dynstr, vals_by_tag[DT_RUNPATH][0]) if DT_RUNPATH in vals_by_tag else None

    def _parse_dynsym(self):
        self.defined = set()
        self.undefined = set()
        self.undefined_strong = set()
        self.undefined_weak = set()
        for section in self.sections:
            if section["type"] != SHT_DYNSYM or not section["entsize"]:
                continue
            if section["link"] >= len(self.sections):
                continue
            strsec = self.sections[section["link"]]
            dynstr = self.data[strsec["offset"] : strsec["offset"] + strsec["size"]]
            count = section["size"] // section["entsize"]
            for i in range(count):
                off = section["offset"] + i * section["entsize"]
                if self.bits == 64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = self._unpack("IBBHQQ", off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = self._unpack("IIIBBH", off)
                name = self._cstr(dynstr, st_name)
                if not name:
                    continue
                bind = st_info >> 4
                visibility = st_other & 3
                # Only global/weak, default/protected symbols participate in normal lookup.
                if bind not in (1, 2) or visibility not in (0, 3):
                    continue
                if st_shndx == SHN_UNDEF:
                    self.undefined.add(name)
                    if bind == 2:
                        self.undefined_weak.add(name)
                    else:
                        self.undefined_strong.add(name)
                else:
                    self.defined.add(name)

    def as_dict(self):
        return {
            "path": str(self.path),
            "bits": self.bits,
            "machine": self.e_machine,
            "type": self.e_type,
            "interpreter": self.interpreter,
            "needed": self.needed,
            "soname": self.soname,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "defined": sorted(self.defined),
            "undefined": sorted(self.undefined),
            "undefined_strong": sorted(self.undefined_strong),
            "undefined_weak": sorted(self.undefined_weak),
        }


def iter_elfs(root: Path):
    for path in root.rglob("*"):
        try:
            if not path.is_file():
                continue
            with path.open("rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            yield path, Elf(path)
        except OSError:
            # Windows cannot follow the Linux symlinks materialized by the
            # cpio extractor.  They are not distinct ELF payloads anyway.
            continue
        except (ElfError, struct.error) as exc:
            print(f"warning: {path}: {exc}", file=os.sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args()
    rows = []
    for raw in ns.paths:
        path = Path(raw)
        if path.is_dir() or ns.recursive:
            rows.extend(e.as_dict() for _p, e in iter_elfs(path))
        else:
            rows.append(Elf(path).as_dict())
    if ns.json:
        json.dump(rows, os.sys.stdout, indent=2)
        print()
        return
    for row in rows:
        print(row["path"])
        print(f"  ELF{row['bits']} machine={row['machine']} interp={row['interpreter']}")
        print(f"  needed={','.join(row['needed'])}")
        if row["rpath"] or row["runpath"]:
            print(f"  rpath={row['rpath']} runpath={row['runpath']}")
        print(f"  dynsym defined={len(row['defined'])} undefined={len(row['undefined'])}")


if __name__ == "__main__":
    main()
