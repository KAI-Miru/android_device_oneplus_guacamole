#!/usr/bin/env python3
"""Apply the narrowly scoped H.40 recovery Keystore 2 permission shim.

The TeamWin android-12.1 Keystore 2 daemon normally checks the Android 12
``keystore2`` and ``keystore2_key`` SELinux userspace classes.  The preserved
H.40/SDK30 recovery policy predates those classes and is configured to deny
unknown classes even while the recovery domain itself is permissive.

This transform bypasses only the three checks used by TWRP's synthetic-password
unwrap path, and only for a root Binder caller whose supplied SID is exactly
``u:r:recovery:s0``:

* ``add_auth`` on the Keystore 2 service;
* ``get_info`` on locksettings namespace 103; and
* ``use`` on locksettings namespace 103.

All other callers, domains, namespaces and permissions retain the upstream
checks.  TWRP must request a non-forced createOperation; ``req_forced_op`` is
intentionally not bypassed.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PINNED_SYSTEM_SECURITY_COMMIT = "14737db1429b8eebc15568bc748b2cd79ccad5c2"
PINNED_UTILS_GIT_BLOB = "a110c64ebe76846c96bb297965182d013c775d29"
TARGET = Path("keystore2/src/utils.rs")
MARKER = "H40_RECOVERY_KEYSTORE2_PERMISSION_SHIM_V51"


IMPORT_OLD = """use android_system_keystore2::aidl::android::system::keystore2::{
    Authorization::Authorization, KeyDescriptor::KeyDescriptor,
};
"""

IMPORT_NEW = """use android_system_keystore2::aidl::android::system::keystore2::{
    Authorization::Authorization, Domain::Domain, KeyDescriptor::KeyDescriptor,
};
"""

ANCHOR_OLD = """use std::sync::Mutex;

/// This function uses its namesake in the permission module and in
"""

ANCHOR_NEW = f"""use std::sync::Mutex;

const H40_RECOVERY_PERMISSION_MARKER: &str = \"{MARKER}\";
const H40_RECOVERY_CALLER_SID: &[u8] = b\"u:r:recovery:s0\";
const H40_LOCKSETTINGS_NAMESPACE: i64 = 103;

fn is_h40_recovery_caller(calling_uid: u32, calling_sid: &std::ffi::CStr) -> bool {{
    calling_uid == 0 && calling_sid.to_bytes() == H40_RECOVERY_CALLER_SID
}}

fn allow_h40_recovery_keystore_permission(
    calling_uid: u32,
    calling_sid: &std::ffi::CStr,
    perm: KeystorePerm,
) -> bool {{
    is_h40_recovery_caller(calling_uid, calling_sid) && perm == KeystorePerm::add_auth()
}}

fn allow_h40_recovery_key_permission(
    calling_uid: u32,
    calling_sid: &std::ffi::CStr,
    perm: KeyPerm,
    key: &KeyDescriptor,
) -> bool {{
    is_h40_recovery_caller(calling_uid, calling_sid)
        && key.domain == Domain::SELINUX
        && key.nspace == H40_LOCKSETTINGS_NAMESPACE
        && (perm == KeyPerm::get_info() || perm == KeyPerm::use_())
}}

/// This function uses its namesake in the permission module and in
"""

CHECK_KEYSTORE_OLD = """pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_keystore_permission(
            &calling_sid.ok_or_else(Error::sys).context(
                "In check_keystore_permission: Cannot check permission without calling_sid.",
            )?,
            perm,
        )
    })
}
"""

CHECK_KEYSTORE_NEW = """pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        let calling_sid = calling_sid.ok_or_else(Error::sys).context(
            "In check_keystore_permission: Cannot check permission without calling_sid.",
        )?;
        if allow_h40_recovery_keystore_permission(
            ThreadState::get_calling_uid(),
            calling_sid,
            perm,
        ) {
            log::warn!(
                "{}: allowing add_auth for root recovery Binder caller",
                H40_RECOVERY_PERMISSION_MARKER
            );
            return Ok(());
        }
        permission::check_keystore_permission(calling_sid, perm)
    })
}
"""

CHECK_KEY_OLD = """pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_key_permission(
            ThreadState::get_calling_uid(),
            &calling_sid
                .ok_or_else(Error::sys)
                .context("In check_key_permission: Cannot check permission without calling_sid.")?,
            perm,
            key,
            access_vector,
        )
    })
}
"""

CHECK_KEY_NEW = """pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        let calling_uid = ThreadState::get_calling_uid();
        let calling_sid = calling_sid
            .ok_or_else(Error::sys)
            .context("In check_key_permission: Cannot check permission without calling_sid.")?;
        if allow_h40_recovery_key_permission(calling_uid, calling_sid, perm, key) {
            log::warn!(
                "{}: allowing locksettings key access for root recovery Binder caller",
                H40_RECOVERY_PERMISSION_MARKER
            );
            return Ok(());
        }
        permission::check_key_permission(calling_uid, calling_sid, perm, key, access_vector)
    })
}
"""

TEST_OLD = """    #[test]
    fn check_device_attestation_permissions_test() -> Result<()> {
        check_device_attestation_permissions().or_else(|error| {
            match error.root_cause().downcast_ref::<Error>() {
                // Expected: the context for this test might not be allowed to attest device IDs.
                Some(Error::Km(ErrorCode::CANNOT_ATTEST_IDS)) => Ok(()),
                // Other errors are unexpected
                _ => Err(error),
            }
        })
    }
}
"""

TEST_NEW = """    #[test]
    fn check_device_attestation_permissions_test() -> Result<()> {
        check_device_attestation_permissions().or_else(|error| {
            match error.root_cause().downcast_ref::<Error>() {
                // Expected: the context for this test might not be allowed to attest device IDs.
                Some(Error::Km(ErrorCode::CANNOT_ATTEST_IDS)) => Ok(()),
                // Other errors are unexpected
                _ => Err(error),
            }
        })
    }

    #[test]
    fn h40_recovery_permission_shim_is_exact_and_narrow() {
        let recovery = std::ffi::CStr::from_bytes_with_nul(b"u:r:recovery:s0\\0").unwrap();
        let near_match = std::ffi::CStr::from_bytes_with_nul(b"u:r:recovery:s0x\\0").unwrap();
        let locksettings = KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: H40_LOCKSETTINGS_NAMESPACE,
            alias: None,
            blob: None,
        };
        let wrong_namespace = KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: H40_LOCKSETTINGS_NAMESPACE + 1,
            alias: None,
            blob: None,
        };
        let wrong_domain = KeyDescriptor {
            domain: Domain::APP,
            nspace: H40_LOCKSETTINGS_NAMESPACE,
            alias: None,
            blob: None,
        };

        assert!(allow_h40_recovery_keystore_permission(
            0,
            recovery,
            KeystorePerm::add_auth()
        ));
        assert!(!allow_h40_recovery_keystore_permission(
            0,
            recovery,
            KeystorePerm::reset()
        ));
        assert!(!allow_h40_recovery_keystore_permission(
            1,
            recovery,
            KeystorePerm::add_auth()
        ));
        assert!(!allow_h40_recovery_keystore_permission(
            0,
            near_match,
            KeystorePerm::add_auth()
        ));

        assert!(allow_h40_recovery_key_permission(
            0,
            recovery,
            KeyPerm::get_info(),
            &locksettings
        ));
        assert!(allow_h40_recovery_key_permission(
            0,
            recovery,
            KeyPerm::use_(),
            &locksettings
        ));
        assert!(!allow_h40_recovery_key_permission(
            0,
            recovery,
            KeyPerm::req_forced_op(),
            &locksettings
        ));
        assert!(!allow_h40_recovery_key_permission(
            1,
            recovery,
            KeyPerm::use_(),
            &locksettings
        ));
        assert!(!allow_h40_recovery_key_permission(
            0,
            near_match,
            KeyPerm::use_(),
            &locksettings
        ));
        assert!(!allow_h40_recovery_key_permission(
            0,
            recovery,
            KeyPerm::use_(),
            &wrong_namespace
        ));
        assert!(!allow_h40_recovery_key_permission(
            0,
            recovery,
            KeyPerm::use_(),
            &wrong_domain
        ));
    }
}
"""


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def replace_exact(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact source block, found {count}")
    return text.replace(old, new, 1)


def validate_patched(text: str) -> None:
    required = (
        MARKER,
        'calling_uid == 0 && calling_sid.to_bytes() == H40_RECOVERY_CALLER_SID',
        'key.domain == Domain::SELINUX',
        'key.nspace == H40_LOCKSETTINGS_NAMESPACE',
        'perm == KeystorePerm::add_auth()',
        'perm == KeyPerm::get_info() || perm == KeyPerm::use_()',
        'assert!(!allow_h40_recovery_key_permission(',
        'KeyPerm::req_forced_op()',
    )
    for needle in required:
        if needle not in text:
            raise SystemExit(f"patched source is missing required contract: {needle}")
    if text.count(MARKER) != 1:
        raise SystemExit("patched source marker is not unique")
    allow_start = text.index("fn allow_h40_recovery_key_permission")
    allow_end = text.index("/// This function uses its namesake", allow_start)
    allow_body = text[allow_start:allow_end]
    if "req_forced_op" in allow_body:
        raise SystemExit("req_forced_op must not be part of the recovery bypass")
    if "Domain::BLOB" in allow_body or "Domain::APP" in allow_body:
        raise SystemExit("recovery key bypass widened beyond Domain::SELINUX")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("system_security_root", type=Path)
    args = parser.parse_args()

    target = args.system_security_root / TARGET
    original = target.read_bytes()
    actual_blob = git_blob_sha1(original)
    if actual_blob != PINNED_UTILS_GIT_BLOB:
        raise SystemExit(
            f"refusing source drift for {TARGET}: expected Git blob "
            f"{PINNED_UTILS_GIT_BLOB}, got {actual_blob}; pinned repository commit is "
            f"{PINNED_SYSTEM_SECURITY_COMMIT}"
        )
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{TARGET} is not UTF-8") from exc

    text = replace_exact(text, IMPORT_OLD, IMPORT_NEW, "Domain import")
    text = replace_exact(text, ANCHOR_OLD, ANCHOR_NEW, "recovery helper anchor")
    text = replace_exact(
        text, CHECK_KEYSTORE_OLD, CHECK_KEYSTORE_NEW, "Keystore service permission wrapper"
    )
    text = replace_exact(text, CHECK_KEY_OLD, CHECK_KEY_NEW, "key permission wrapper")
    text = replace_exact(text, TEST_OLD, TEST_NEW, "narrowness unit tests")
    validate_patched(text)

    target.write_text(text, encoding="utf-8", newline="\n")
    print(
        f"applied {MARKER} to {target} "
        f"(TeamWin system/security {PINNED_SYSTEM_SECURITY_COMMIT})"
    )


if __name__ == "__main__":
    main()
