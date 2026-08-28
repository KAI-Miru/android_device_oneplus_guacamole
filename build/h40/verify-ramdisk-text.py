#!/usr/bin/env python3
"""Reject CR bytes in recovery configuration and H.40 build inputs."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TEXT_SUFFIXES = {
    ".flags",
    ".fstab",
    ".json",
    ".mk",
    ".patch",
    ".prop",
    ".py",
    ".rc",
    ".sh",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_ROOTS = (
    REPO_ROOT / ".github",
    REPO_ROOT / "build" / "h40",
    REPO_ROOT / "recovery" / "root",
    REPO_ROOT / "prebuilt" / "h40",
)


def main() -> None:
    candidates = sorted(
        path
        for root in TEXT_ROOTS
        for path in root.rglob("*")
        if path.is_file() and path.suffix in TEXT_SUFFIXES
    )
    if not candidates:
        raise SystemExit("no ramdisk text inputs were found")

    failures = []
    for path in candidates:
        payload = path.read_bytes()
        if b"\r" in payload:
            failures.append(str(path.relative_to(REPO_ROOT)))
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"{path.relative_to(REPO_ROOT)} is not UTF-8: {exc}") from exc

    if failures:
        rendered = "\n".join(f"  {path}" for path in failures)
        raise SystemExit(f"CR bytes are forbidden in ramdisk text inputs:\n{rendered}")
    print(f"verified {len(candidates)} UTF-8/LF ramdisk text inputs")


if __name__ == "__main__":
    main()
