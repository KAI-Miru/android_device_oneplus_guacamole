#!/usr/bin/env python3
"""Fail-closed validation for the H.40 V5.1 Keystore 2 permission shim."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


TARGET = Path("keystore2/src/utils.rs")
MARKER = "H40_RECOVERY_KEYSTORE2_PERMISSION_SHIM_V51"
EXPECTED_PATCHED_SHA256 = "01e37c389548903ac2c9e175fea3310786a1431ea9e1d5578788feae3fa2417d"


def require(text: str, needle: str) -> None:
    if needle not in text:
        raise SystemExit(f"missing V5.1 permission-shim contract: {needle}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("system_security_root", type=Path)
    args = parser.parse_args()

    target = args.system_security_root / TARGET
    data = target.read_bytes()
    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != EXPECTED_PATCHED_SHA256:
        raise SystemExit(
            f"refusing transformed-source drift for {TARGET}: expected SHA-256 "
            f"{EXPECTED_PATCHED_SHA256}, got {actual_sha256}"
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{TARGET} is not UTF-8") from exc

    if text.count(MARKER) != 1:
        raise SystemExit("the V5.1 source marker must occur exactly once")

    required = (
        'const H40_RECOVERY_CALLER_SID: &[u8] = b"u:r:recovery:s0";',
        "const H40_LOCKSETTINGS_NAMESPACE: i64 = 103;",
        "calling_uid == 0 && calling_sid.to_bytes() == H40_RECOVERY_CALLER_SID",
        "perm == KeystorePerm::add_auth()",
        "key.domain == Domain::SELINUX",
        "key.nspace == H40_LOCKSETTINGS_NAMESPACE",
        "perm == KeyPerm::get_info() || perm == KeyPerm::use_()",
        "permission::check_keystore_permission(calling_sid, perm)",
        "permission::check_key_permission(calling_uid, calling_sid, perm, key, access_vector)",
        "fn h40_recovery_permission_shim_is_exact_and_narrow()",
        "KeyPerm::req_forced_op()",
        "KeystorePerm::reset()",
        "let wrong_namespace = KeyDescriptor",
        "let wrong_domain = KeyDescriptor",
    )
    for needle in required:
        require(text, needle)

    helper_start = text.index("fn allow_h40_recovery_keystore_permission")
    helper_end = text.index("/// This function uses its namesake", helper_start)
    helpers = text[helper_start:helper_end]
    forbidden_in_bypass = (
        "req_forced_op",
        "KeystorePerm::reset",
        "Domain::APP",
        "Domain::BLOB",
        "Domain::GRANT",
        "Domain::KEY_ID",
    )
    for needle in forbidden_in_bypass:
        if needle in helpers:
            raise SystemExit(f"recovery bypass was widened unexpectedly: {needle}")

    print(f"validated {MARKER} in {target} ({actual_sha256})")


if __name__ == "__main__":
    main()
