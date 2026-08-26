#!/usr/bin/env python3
"""Apply the H.40 V5.1 parent-process modern CE handoff.

This is an intentionally small delta on top of the canonical V5.0 transform.
V5.0 ran TeamWin's synthetic-password and FsCrypt work in a forked child.  A
successful child could install a kernel fscrypt key, but its GetCePolicies()
and KeyStorage state disappeared at _exit().  V5.1 keeps the exact-H.40 OEM
credential gate isolated, then performs the guarded modern unwrap and CE-key
installation in the long-lived recovery process.
"""

from pathlib import Path
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: apply-h40-v51-parent-keystorage.py RECOVERY_ROOT VOLD_ROOT"
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"V5.1 {label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
partitionmanager_path = recovery_root / "partitionmanager.cpp"
fscrypt_path = vold_root / "FsCrypt.cpp"
fscrypt_header_path = vold_root / "FsCrypt.h"
decrypt_path = vold_root / "Decrypt.cpp"
decrypt_header_path = vold_root / "Decrypt.h"

partitionmanager = partitionmanager_path.read_text()
fscrypt = fscrypt_path.read_text()
fscrypt_header = fscrypt_header_path.read_text()
decrypt = decrypt_path.read_text()
decrypt_header = decrypt_header_path.read_text()

if "[H40 V51 PARENT]" in partitionmanager or "[H40 V51 CURRENT]" in fscrypt:
    raise SystemExit("V5.1 parent-keystorage transform already applied")
for marker, source in (
    ("[H40 V50 HANDOFF]", partitionmanager),
    ("Result::kModernHandoff", partitionmanager),
    ("bool authorization_failed = false;", decrypt),
    ("[H40 FSCRYPTMODE]", fscrypt),
):
    if marker not in source:
        raise SystemExit(f"V5.1 requires canonical V5.0 source marker: {marker}")

partitionmanager = replace_once(
    partitionmanager,
    "#include <sys/wait.h>\n#include <sys/prctl.h>\n#include <signal.h>\n",
    "#include <sys/wait.h>\n",
    "obsolete child-isolation headers",
)

old_child_worker = '''enum class ModernDecryptResult {
\tkSuccess,
\tkFailure,
\tkFatalFailure,
};

ModernDecryptResult RunModernDecryptIsolated(int user_id, const std::string& password) {
\tconst pid_t pid = fork();
\tif (pid < 0) {
\t\tLOGERR("[H40 V50 HANDOFF] failed to fork modern decrypt worker: %s\\n", strerror(errno));
\t\treturn ModernDecryptResult::kFatalFailure;
\t}
\tif (pid == 0) {
\t\t// Decrypt_User is existing TeamWin code. Run it in a disposable child so
\t\t// malformed SP/Keymaster input cannot terminate the recovery UI process.
\t\tif (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1 ||
\t\t\tprctl(PR_SET_DUMPABLE, 0) != 0) {
\t\t\t_exit(2);
\t\t}
\t\tconst bool decrypted = android::keystore::Decrypt_User(user_id, password);
\t\t_exit(decrypted ? 0 : 1);
\t}

\t// TeamWin already uses this bounded child-wait primitive for legacy
\t// decryption. A timeout, signal, wait error, or unknown exit code is fatal.
\tint status = 0x7f;
\tif (TWFunc::Wait_For_Child_Timeout(pid, &status, "H40 modern decrypt", 120) != 0 ||
\t\t!WIFEXITED(status)) {
\t\treturn ModernDecryptResult::kFatalFailure;
\t}
\tif (WEXITSTATUS(status) == 0) return ModernDecryptResult::kSuccess;
\tif (WEXITSTATUS(status) == 1) return ModernDecryptResult::kFailure;
\treturn ModernDecryptResult::kFatalFailure;
}

'''
partitionmanager = replace_once(
    partitionmanager,
    old_child_worker,
    "",
    "fork-only modern decrypt worker",
)

old_dispatch = '''\t\t} else if (oplus_result == twrp::oplus_h40::Result::kModernHandoff) {
\t\t\ttry_generic_decrypt = false;
\t\t\tLOGINFO("[H40 V50 HANDOFF] deriving the accepted user 0 credential in an isolated TeamWin SP worker\\n");
\t\t\tconst ModernDecryptResult modern_result =
\t\t\t\tRunModernDecryptIsolated(user_id, Password);
\t\t\tconst bool modern_decrypt = modern_result == ModernDecryptResult::kSuccess;
\t\t\tdecrypt_success = twrp::oplus_h40::CompleteModernHandoff(modern_decrypt) ==
\t\t\t\ttwrp::oplus_h40::Result::kSuccess;
\t\t\tif (!decrypt_success) {
\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t}
'''
new_dispatch = '''\t\t} else if (oplus_result == twrp::oplus_h40::Result::kModernHandoff) {
\t\t\ttry_generic_decrypt = false;
\t\t\t// The OEM verifier remains isolated.  TeamWin SP unwrap and the
\t\t\t// current-only FsCrypt install must run here so the recovery process
\t\t\t// retains GetCePolicies() and KeyStorage state after this call.
\t\t\tLOGINFO("[H40 V51 PARENT] deriving and installing the accepted user 0 credential in the recovery parent\\n");
\t\t\tconst bool modern_decrypt =
\t\t\t\tandroid::keystore::Decrypt_User_H40_Modern(user_id, Password);
\t\t\tdecrypt_success = twrp::oplus_h40::CompleteModernHandoff(modern_decrypt) ==
\t\t\t\ttwrp::oplus_h40::Result::kSuccess;
\t\t\tif (!decrypt_success) {
\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t}
'''
partitionmanager = replace_once(
    partitionmanager, old_dispatch, new_dispatch, "parent-process handoff dispatch"
)

decrypt_header = replace_once(
    decrypt_header,
    '''    bool Decrypt_User(const userid_t user_id, const std::string& Password);
''',
    '''    bool Decrypt_User(const userid_t user_id, const std::string& Password);
    bool Decrypt_User_H40_Modern(const userid_t user_id, const std::string& Password);
''',
    "modern decrypt declaration",
)

decrypt = replace_once(
    decrypt,
    '''bool Decrypt_User_Synth_Pass(const userid_t user_id, const std::string& Password) {
\tprintf("Attempting to decrypt user's synthetic password\\n");
''',
    '''static bool Decrypt_User_Synth_Pass_Impl(const userid_t user_id,
\t\tconst std::string& Password, bool h40_current_only) {
\tif (h40_current_only &&
\t\t(user_id != 0 || Password.empty() || Password == "!")) {
\t\tprintf("[H40 V51 PARENT] refusing invalid current-only synthetic-password request\\n");
\t\treturn false;
\t}
\tprintf("Attempting to decrypt user's synthetic password\\n");
''',
    "synthetic-password implementation split",
)

decrypt = replace_once(
    decrypt,
    '''\tstd::string unwrapSyntheticPasswordBlob(const std::string& spblob_path, const std::string& handle_str, const userid_t user_id,
\t\tconst void* application_id, const size_t application_id_size, uint32_t auth_token_len) {
''',
    '''\tstd::string unwrapSyntheticPasswordBlob(const std::string& spblob_path, const std::string& handle_str, const userid_t user_id,
\t\tconst void* application_id, const size_t application_id_size, uint32_t auth_token_len,
\t\tbool forced_operation) {
''',
    "synthetic-password forced-operation parameter",
)

decrypt = replace_once(
    decrypt,
    '''\t\t\tauto begin_rc = keyResponse.iSecurityLevel->createOperation(
\t\t\t\tkeyResponse.metadata.key, begin_params.vector_data(), true,
\t\t\t\t&encOperationResponse);
''',
    '''\t\t\tauto begin_rc = keyResponse.iSecurityLevel->createOperation(
\t\t\t\tkeyResponse.metadata.key, begin_params.vector_data(), forced_operation,
\t\t\t\t&encOperationResponse);
''',
    "narrow Keystore2 forced-operation selector",
)

decrypt = replace_once(
    decrypt,
    '''\tsecret = android::keystore::unwrapSyntheticPasswordBlob(spblob_path, handle_str, user_id, (const void*)&application_id[0], 
\t\tPASSWORD_TOKEN_SIZE + SHA512_DIGEST_LENGTH, auth_token_len);
''',
    '''\t// Preserve TeamWin's canonical forced operation for every ordinary call.
\t// H.40's current-only path must not require the req_forced_op SELinux
\t// permission, so only that exact selector reaches Keystore2 with false.
\tconst bool forced_operation = !h40_current_only;
\tif (h40_current_only) {
\t\tprintf("[H40 V51 FORCEDOP] requesting an ordinary Keystore2 operation\\n");
\t}
\tsecret = android::keystore::unwrapSyntheticPasswordBlob(spblob_path, handle_str, user_id,
\t\t(const void*)&application_id[0], PASSWORD_TOKEN_SIZE + SHA512_DIGEST_LENGTH,
\t\tauth_token_len, forced_operation);
''',
    "H40-only non-forced operation call",
)

decrypt = replace_once(
    decrypt,
    '''\tif (!Decrypt_CE_storage(user_id, token, secret)) {
\t\treturn Free_Return(retval, weaver_key, &pwd);
\t}

\tretval = true;
''',
    '''\tif (h40_current_only) {
\t\tif (!fscrypt_unlock_user0_key_current_only(secret)) {
\t\t\tprintf("[H40 V51 PARENT] guarded current-only CE key install failed\\n");
\t\t\treturn Free_Return(retval, weaver_key, &pwd);
\t\t}
\t} else if (!Decrypt_CE_storage(user_id, token, secret)) {
\t\treturn Free_Return(retval, weaver_key, &pwd);
\t}

\tretval = true;
''',
    "current-only final storage step",
)

decrypt = replace_once(
    decrypt,
    '''\tretval = true;
\treturn Free_Return(retval, weaver_key, &pwd);
}

extern "C" int Get_Password_Type''',
    '''\tretval = true;
\treturn Free_Return(retval, weaver_key, &pwd);
}

bool Decrypt_User_Synth_Pass(const userid_t user_id, const std::string& Password) {
\treturn Decrypt_User_Synth_Pass_Impl(user_id, Password, false);
}

extern "C" bool Decrypt_User_H40_Modern(const userid_t user_id,
\t\tconst std::string& Password) {
\tif (user_id != 0 || Password.empty() || Password == "!") {
\t\tprintf("[H40 V51 PARENT] refusing non-user0 or empty/default credential\\n");
\t\treturn false;
\t}
\treturn Decrypt_User_Synth_Pass_Impl(user_id, Password, true);
}

extern "C" int Get_Password_Type''',
    "public modern decrypt wrapper",
)

fscrypt_header = replace_once(
    fscrypt_header,
    '''bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& secret);
''',
    '''bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& secret);
// H.40 recovery-only path: exact user-0/current direct-AES layout, no key-dir
// fixating, creation, rename, upgrade, or user-storage preparation.
bool fscrypt_unlock_user0_key_current_only(const std::string& secret_hex);
''',
    "current-only FsCrypt declaration",
)

old_auth_tail = '''static std::optional<android::vold::KeyAuthentication> authentication_from_hex(
        const std::string& secret_hex) {
    std::string secret;
    if (!parse_hex(secret_hex, &secret)) return std::optional<android::vold::KeyAuthentication>();
    if (secret.empty()) {
        return GetEmptyAuthentication();
    } else {
        return android::vold::KeyAuthentication(secret);
    }
}

'''
new_auth_tail = old_auth_tail + r'''// H.40's ColorOS key directory is accepted only in this exact direct-AES
// shape.  Every path component is opened relative to its already-validated
// parent with O_NOFOLLOW; the guard never creates, renames, or unlinks files.
static bool h40_open_directory_at(int parent_fd, const char* name,
                                  android::base::unique_fd* result) {
    const int fd = TEMP_FAILURE_RETRY(
            openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "[H40 V51 CURRENT] cannot open directory component " << name;
        return false;
    }
    struct stat status = {};
    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode)) {
        PLOG(ERROR) << "[H40 V51 CURRENT] invalid directory component " << name;
        close(fd);
        return false;
    }
    result->reset(fd);
    return true;
}

static bool h40_directory_has_exact_entries(int directory_fd,
                                             const std::set<std::string>& expected,
                                             const char* label) {
    const int scan_fd = TEMP_FAILURE_RETRY(
            fcntl(directory_fd, F_DUPFD_CLOEXEC, 0));
    if (scan_fd < 0) {
        PLOG(ERROR) << "[H40 V51 CURRENT] cannot duplicate " << label;
        return false;
    }
    auto directory = std::unique_ptr<DIR, int (*)(DIR*)>(fdopendir(scan_fd), closedir);
    if (!directory) {
        PLOG(ERROR) << "[H40 V51 CURRENT] cannot enumerate " << label;
        close(scan_fd);
        return false;
    }

    std::set<std::string> seen;
    errno = 0;
    while (dirent* entry = readdir(directory.get())) {
        const std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (expected.count(name) == 0 || !seen.insert(name).second) {
            LOG(ERROR) << "[H40 V51 CURRENT] unexpected entry " << label << "/" << name;
            return false;
        }
        errno = 0;
    }
    if (errno != 0) {
        PLOG(ERROR) << "[H40 V51 CURRENT] failed while enumerating " << label;
        return false;
    }
    if (seen != expected) {
        LOG(ERROR) << "[H40 V51 CURRENT] missing required entry in " << label;
        return false;
    }
    return true;
}

static bool h40_validate_regular_file_at(int directory_fd, const char* name,
                                         off_t expected_size,
                                         const char* expected_contents) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(
            openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "[H40 V51 CURRENT] cannot open " << name;
        return false;
    }
    struct stat status = {};
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_nlink != 1 || status.st_size != expected_size) {
        LOG(ERROR) << "[H40 V51 CURRENT] malformed " << name
                   << ": mode=" << status.st_mode
                   << " links=" << status.st_nlink << " size=" << status.st_size;
        return false;
    }

    std::string contents(static_cast<size_t>(expected_size), '\0');
    size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = TEMP_FAILURE_RETRY(
                read(fd.get(), &contents[offset], contents.size() - offset));
        if (count <= 0) {
            PLOG(ERROR) << "[H40 V51 CURRENT] short read from " << name;
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    char extra = 0;
    if (TEMP_FAILURE_RETRY(read(fd.get(), &extra, 1)) != 0) {
        LOG(ERROR) << "[H40 V51 CURRENT] grew while reading " << name;
        return false;
    }
    if (expected_contents != nullptr && contents != expected_contents) {
        LOG(ERROR) << "[H40 V51 CURRENT] invalid contents in " << name;
        return false;
    }
    return true;
}

static bool validate_h40_modern_user0_ce_layout() {
    android::base::unique_fd root(TEMP_FAILURE_RETRY(
            open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)));
    if (root < 0) {
        PLOG(ERROR) << "[H40 V51 CURRENT] cannot open filesystem root";
        return false;
    }

    android::base::unique_fd data, misc, vold, user_keys, ce, user0, current;
    if (!h40_open_directory_at(root.get(), "data", &data) ||
        !h40_open_directory_at(data.get(), "misc", &misc) ||
        !h40_open_directory_at(misc.get(), "vold", &vold) ||
        !h40_open_directory_at(vold.get(), "user_keys", &user_keys) ||
        !h40_open_directory_at(user_keys.get(), "ce", &ce) ||
        !h40_open_directory_at(ce.get(), "0", &user0)) {
        return false;
    }
    if (!h40_directory_has_exact_entries(user0.get(), {"current"},
                                         "/data/misc/vold/user_keys/ce/0")) {
        return false;
    }
    if (!h40_open_directory_at(user0.get(), "current", &current) ||
        !h40_directory_has_exact_entries(current.get(), {"encrypted_key", "version"},
                                         "/data/misc/vold/user_keys/ce/0/current")) {
        return false;
    }
    if (!h40_validate_regular_file_at(current.get(), "version", 1, "1")) return false;
    // 12-byte GCM nonce + 64-byte fscrypt key + 16-byte GCM tag.
    if (!h40_validate_regular_file_at(current.get(), "encrypted_key", 92, nullptr)) return false;
    return true;
}

bool fscrypt_unlock_user0_key_current_only(const std::string& secret_hex) {
    constexpr userid_t kUser = 0;
    LOG(INFO) << "[H40 V51 CURRENT] guarded parent-process CE install";
    if (!fscrypt_is_native()) {
        LOG(ERROR) << "[H40 V51 CURRENT] native fscrypt is not active";
        return false;
    }
    if (GetCePolicies().count(kUser) != 0) {
        LOG(ERROR) << "[H40 V51 CURRENT] user 0 CE policy already exists";
        return false;
    }
    if (!validate_h40_modern_user0_ce_layout()) return false;

    auto auth = authentication_from_hex(secret_hex);
    if (!auth || auth->secret.empty()) {
        LOG(ERROR) << "[H40 V51 CURRENT] refusing empty or malformed SP-derived secret";
        return false;
    }
    EncryptionOptions options;
    if (!get_data_file_encryption_options(&options) || options.use_hw_wrapped_key) {
        LOG(ERROR) << "[H40 V51 CURRENT] layout requires a non-wrapped data key";
        return false;
    }

    // Re-run the no-follow shape guard immediately before retrieveKey().  With
    // nonempty authentication and no Keymaster/secdiscardable files, the exact
    // accepted layout can take only KeyStorage's read-only direct AES-GCM path.
    if (!validate_h40_modern_user0_ce_layout()) return false;
    const std::string key_path =
            get_ce_key_current_path(get_ce_key_directory_path(kUser));
    KeyBuffer ce_key;
    if (!android::vold::retrieveKey(key_path, *auth, &ce_key)) return false;
    if (ce_key.size() != FSCRYPT_MAX_KEY_SIZE) {
        LOG(ERROR) << "[H40 V51 CURRENT] unexpected recovered CE key size " << ce_key.size();
        return false;
    }

    EncryptionPolicy ce_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, ce_key, &ce_policy)) return false;
    const auto inserted = GetCePolicies().emplace(kUser, ce_policy);
    if (!inserted.second) {
        LOG(ERROR) << "[H40 V51 CURRENT] CE policy insertion raced or duplicated";
        return false;
    }
    LOG(INFO) << "[H40 V51 CURRENT] installed user 0 CE key without key-directory mutation";
    return true;
}

'''
fscrypt = replace_once(
    fscrypt, old_auth_tail, new_auth_tail, "guarded current-only FsCrypt API"
)

# Validate the security boundary before writing any source file.
for forbidden in (
    "RunModernDecryptIsolated",
    "ModernDecryptResult",
    "PR_SET_PDEATHSIG",
    "PR_SET_DUMPABLE",
    'Wait_For_Child_Timeout(pid, &status, "H40 modern decrypt"',
):
    if forbidden in partitionmanager:
        raise SystemExit(f"V5.1 obsolete fork handoff survived: {forbidden}")
for required in (
    "[H40 V51 PARENT]",
    "Decrypt_User_H40_Modern(user_id, Password)",
    "CompleteModernHandoff(modern_decrypt)",
):
    if required not in partitionmanager:
        raise SystemExit(f"V5.1 parent dispatch contract missing: {required}")
for required in (
    "Decrypt_User_Synth_Pass_Impl",
    "bool h40_current_only",
    "uint32_t auth_token_len,\n\t\tbool forced_operation",
    "begin_params.vector_data(), forced_operation",
    "const bool forced_operation = !h40_current_only;",
    "[H40 V51 FORCEDOP]",
    "fscrypt_unlock_user0_key_current_only(secret)",
    "Decrypt_User_Synth_Pass_Impl(user_id, Password, false)",
    "Decrypt_User_Synth_Pass_Impl(user_id, Password, true)",
    "user_id != 0 || Password.empty() || Password == \"!\"",
):
    if required not in decrypt:
        raise SystemExit(f"V5.1 modern decrypt contract missing: {required}")
if decrypt.count("createOperation(") != 1:
    raise SystemExit("V5.1 expected exactly one Keystore2 createOperation call")
if "begin_params.vector_data(), true," in decrypt:
    raise SystemExit("V5.1 canonical forced=true literal survived the narrow selector")
for required in (
    "validate_h40_modern_user0_ce_layout()",
    "O_NOFOLLOW",
    'h40_directory_has_exact_entries(user0.get(), {"current"}',
    '{"encrypted_key", "version"}',
    '"version", 1, "1"',
    '"encrypted_key", 92, nullptr',
    "status.st_nlink != 1",
    "auth->secret.empty()",
    "options.use_hw_wrapped_key",
    "get_ce_key_current_path(get_ce_key_directory_path(kUser))",
    "android::vold::retrieveKey(key_path, *auth, &ce_key)",
    "install_storage_key(DATA_MNT_POINT, options, ce_key, &ce_policy)",
    "GetCePolicies().emplace(kUser, ce_policy)",
):
    if required not in fscrypt:
        raise SystemExit(f"V5.1 current-only FsCrypt contract missing: {required}")
current_only_body = fscrypt.split(
    "bool fscrypt_unlock_user0_key_current_only", 1
)[1].split("static std::string volkey_path", 1)[0]
for forbidden in (
    "fixate_user_ce_key",
    "read_and_fixate_user_ce_key",
    "fscrypt_prepare_user_storage",
    "storeKey",
    "rename(",
    "unlink(",
    "MkdirsSync",
):
    if forbidden in current_only_body:
        raise SystemExit(f"V5.1 current-only path can mutate key storage: {forbidden}")
if "Decrypt_User_H40_Modern" not in decrypt_header:
    raise SystemExit("V5.1 Decrypt.h declaration missing")
if "fscrypt_unlock_user0_key_current_only" not in fscrypt_header:
    raise SystemExit("V5.1 FsCrypt.h declaration missing")

for path, source in (
    (partitionmanager_path, partitionmanager),
    (fscrypt_path, fscrypt),
    (fscrypt_header_path, fscrypt_header),
    (decrypt_path, decrypt),
    (decrypt_header_path, decrypt_header),
):
    with path.open("w", newline="\n") as stream:
        stream.write(source)

print("Applied H.40 V5.1 parent-process modern CE handoff")
print("  OEM credential verification: remains isolated and exact-H.40-only")
print("  SP/Keystore2/FsCrypt state: retained in the recovery parent process")
print("  Keystore2 operation: forced=true ordinarily; false only for H.40 current-only")
print("  key layout: exact user-0/current direct-AES shape, traversed O_NOFOLLOW")
print("  key directory: read-only; no fixate, preparation, rename, or upgrade path")
print("  every invalid layout, user, credential, or install result fails closed")
