#!/usr/bin/env python3
"""Strict manifest and stock-CPIO validation for the H.40 dlopen payload.

This module intentionally contains no payload bytes.  The only accepted blob
source is ``system/lib64`` in the stock CPIO supplied to the hybrid builder.
The external manifest is an allow-list of exact sizes and SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


DESTINATION_DIRECTORY = "/system/tw/lib64"
ROOT_LIBRARY = "libdecrypt_recovery.so"
SOURCE_DIRECTORY = "system/lib64"
EXPECTED_ROM = "OnePlus 7 Pro ColorOS 12.1 H.40"
EXPECTED_BOOT_SHA256 = "991cf738f5a6dc874c6261fa073c89182e61935a9493dc27347699c4d0a68792"
EXPECTED_FILES = frozenset(
    {
        ROOT_LIBRARY,
        "libcryptfs_hw.so",
        "libfscrypt.so",
        "vendor.oplus.hardware.cryptoeng@1.0.so",
        "vendor.qti.hardware.cryptfshw@1.0.so",
    }
)
REQUIRED_ROOT_SYMBOLS = (
    "_Z11setup_de_cei",
    "_Z17get_password_typei",
    "_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi",
    "_Z21fscrypt_init_user0_cev",
    "_Z32fscrypt_mount_metadata_encryptedRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
)


class ManifestError(ValueError):
    """The requested H.40 payload manifest or stock payload is invalid."""


@dataclass(frozen=True)
class ManifestFile:
    name: str
    bytes: int
    sha256: str

    @property
    def source(self) -> str:
        return f"{SOURCE_DIRECTORY}/{self.name}"

    @property
    def target(self) -> str:
        return f"{DESTINATION_DIRECTORY.lstrip('/')}/{self.name}"


@dataclass(frozen=True)
class Manifest:
    path: Path
    raw_sha256: str
    document: dict
    files: tuple[ManifestFile, ...]


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def load_manifest(path: Path) -> Manifest:
    """Load and strictly validate the pinned five-file H.40 allow-list."""

    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"invalid UTF-8 JSON manifest {path}: {exc}") from exc
    _require(isinstance(document, dict), "H.40 manifest root must be an object")

    source = document.get("source")
    _require(isinstance(source, dict), "H.40 manifest source must be an object")
    _require(source.get("rom") == EXPECTED_ROM, "H.40 manifest identifies an unexpected ROM")
    _require(
        source.get("boot_sha256") == EXPECTED_BOOT_SHA256,
        "H.40 manifest identifies an unexpected source boot image",
    )
    _require(
        document.get("destination_directory") == DESTINATION_DIRECTORY,
        f"H.40 manifest destination must be {DESTINATION_DIRECTORY}",
    )

    raw_files = document.get("files")
    _require(isinstance(raw_files, list), "H.40 manifest files must be an array")
    _require(len(raw_files) == len(EXPECTED_FILES), "H.40 manifest must contain exactly five files")
    parsed = []
    seen = set()
    for row in raw_files:
        _require(isinstance(row, dict), "H.40 manifest file entry must be an object")
        name = row.get("name")
        size = row.get("bytes")
        digest = row.get("sha256")
        _require(isinstance(name, str) and name, "H.40 manifest file name must be a string")
        _require("/" not in name and "\\" not in name and name not in {".", ".."}, f"unsafe blob name: {name!r}")
        _require(name not in seen, f"duplicate H.40 manifest file: {name}")
        _require(isinstance(size, int) and not isinstance(size, bool) and size > 0, f"bad byte count for {name}")
        _require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"bad SHA-256 for {name}",
        )
        seen.add(name)
        parsed.append(ManifestFile(name=name, bytes=size, sha256=digest))
    _require(seen == EXPECTED_FILES, f"unexpected H.40 blob set: {sorted(seen)}")

    totals = document.get("totals")
    _require(isinstance(totals, dict), "H.40 manifest totals must be an object")
    _require(
        totals.get("bytes") == sum(item.bytes for item in parsed),
        "H.40 manifest total byte count does not match its files",
    )

    # Sorting makes archive and generated-manifest order independent of JSON
    # member/array ordering while retaining the raw manifest digest as evidence.
    return Manifest(
        path=path,
        raw_sha256=sha256(raw),
        document=document,
        files=tuple(sorted(parsed, key=lambda item: item.name)),
    )


def validate_stock_entries(manifest: Manifest, stock_entries: dict) -> dict[str, object]:
    """Return the five validated stock entries, keyed by basename."""

    result = {}
    for item in manifest.files:
        entry = stock_entries.get(item.source)
        _require(entry is not None, f"stock CPIO is missing pinned H.40 blob: {item.source}")
        _require(entry.mode & 0o170000 == 0o100000, f"pinned H.40 blob is not a regular file: {item.source}")
        _require(len(entry.data) == item.bytes, f"pinned H.40 blob has wrong size: {item.source}")
        _require(sha256(entry.data) == item.sha256, f"pinned H.40 blob hash mismatch: {item.source}")
        _require(entry.data[:4] == b"\x7fELF", f"pinned H.40 blob is not ELF: {item.source}")
        result[item.name] = entry
    _require(set(result) == EXPECTED_FILES, "validated H.40 blob set is incomplete")
    return result
