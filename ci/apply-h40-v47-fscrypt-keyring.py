#!/usr/bin/env python3
from pathlib import Path
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: apply-h40-v47-fscrypt-keyring.py RECOVERY_ROOT VOLD_ROOT"
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"V4.7 {label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter_path = recovery_root / "oplus_h40_decrypt.cpp"
fscrypt_path = vold_root / "FsCrypt.cpp"

adapter = adapter_path.read_text()
fscrypt = fscrypt_path.read_text()

for marker in ("[H40 FSCRYPTKEYRING]", "[H40 FSCRYPTMODE]"):
    if marker in adapter or marker in fscrypt:
        raise SystemExit(f"V4.7 transform already applied: {marker}")

adapter = replace_once(
    adapter,
    "#include <hidl/ServiceManagement.h>\n#include <linux/fscrypt.h>\n",
    "#include <hidl/ServiceManagement.h>\n#include <keyutils.h>\n#include <linux/fscrypt.h>\n",
    "keyutils include",
)

adapter = replace_once(
    adapter,
    "RuntimeState& GetRuntimeState();\n\nstd::mutex& GetRuntimeMutex() {\n",
    """RuntimeState& GetRuntimeState();

bool EnsureFscryptSessionKeyring() {
    constexpr char kName[] = "fscrypt";

    errno = 0;
    key_serial_t keyring =
            keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", kName, 0);
    if (keyring >= 0) {
        LOGINFO("[H40 FSCRYPTKEYRING] existing: id=%d\\n", static_cast<int>(keyring));
        return true;
    }
    if (errno != ENOKEY) {
        LOGERR("[H40 FSCRYPTKEYRING] search failed: %s\\n", strerror(errno));
        return false;
    }

    errno = 0;
    keyring = add_key("keyring", kName, nullptr, 0, KEY_SPEC_SESSION_KEYRING);
    if (keyring >= 0) {
        LOGINFO("[H40 FSCRYPTKEYRING] created: id=%d\\n", static_cast<int>(keyring));
        return true;
    }

    const int creation_errno = errno;
    keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", kName, 0);
    if (keyring >= 0) {
        LOGINFO("[H40 FSCRYPTKEYRING] appeared concurrently: id=%d\\n",
                static_cast<int>(keyring));
        return true;
    }

    LOGERR("[H40 FSCRYPTKEYRING] creation failed: %s\\n", strerror(creation_errno));
    return false;
}

std::mutex& GetRuntimeMutex() {
""",
    "session-keyring helper",
)

adapter = replace_once(
    adapter,
    """Result PrepareMetadataRuntime() {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    const Api& api = GetApi();
    if (api.handle == nullptr) return Result::kUnavailable;
""",
    """Result PrepareMetadataRuntime() {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    if (!EnsureFscryptSessionKeyring()) {
        return FailActive("fscrypt session keyring unavailable before metadata decrypt");
    }
    LOGINFO("[H40 FSCRYPTKEYRING] ready before TWRP metadata decrypt\\n");

    const Api& api = GetApi();
    if (api.handle == nullptr) return Result::kUnavailable;
""",
    "all-path pre-metadata keyring ordering",
)

adapter = replace_once(
    adapter,
    """bool PrepareUser0DeState(const Api& api, User0State* user0_state) {
    LOGINFO("Oplus H.40 invoking setup_de_ce(0)\\n");
""",
    """bool PrepareUser0DeState(const Api& api, User0State* user0_state) {
    if (!EnsureFscryptSessionKeyring()) {
        LOGERR("[H40 FSCRYPTKEYRING] refusing setup_de_ce(0) without keyring\\n");
        return false;
    }
    LOGINFO("[H40 FSCRYPTKEYRING] ready before setup_de_ce(0)\\n");
    LOGINFO("Oplus H.40 invoking setup_de_ce(0)\\n");
""",
    "keyring call ordering",
)

fscrypt = replace_once(
    fscrypt,
    "\nbool retry = true;\n\n// Returns KeyGeneration suitable for key as described in EncryptionOptions\n",
    "\n// Returns KeyGeneration suitable for key as described in EncryptionOptions\n",
    "namespace retry removal",
)

fscrypt = replace_once(
    fscrypt,
    """    if (options->version == 1 || !retry) {
        options->use_hw_wrapped_key =
            GetEntryForMountPoint(&GetFstabDefault(), DATA_MNT_POINT)->fs_mgr_flags.wrapped_key;
    }
    return true;
""",
    """    const bool parsed_wrapped_key = options->use_hw_wrapped_key;
    if (options->version == 1 && entry->fs_mgr_flags.wrapped_key) {
        options->use_hw_wrapped_key = true;
    }
    LOG(INFO) << "[H40 FSCRYPTMODE] data options: version=" << options->version
              << " parsedWrapped=" << parsed_wrapped_key
              << " legacyFstabWrapped=" << entry->fs_mgr_flags.wrapped_key
              << " effectiveWrapped=" << options->use_hw_wrapped_key;
    return true;
""",
    "fstab-authoritative key mode",
)

fscrypt = replace_once(
    fscrypt,
    """    KeyBuffer device_key;
install:
    if (!retrieveOrGenerateKey(GetDeviceKeyPath(), GetDeviceKeyTemp(), GetEmptyAuthentication(),
                               makeGen(options), &device_key))
        return false;

    EncryptionPolicy device_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, device_key, &device_policy)) {
        if (retry) {
            printf("Trying %s wrappedkey\\n", options.use_hw_wrapped_key ? "without" : "with");
            GetEntryForMountPoint(&GetFstabDefault(), DATA_MNT_POINT)->fs_mgr_flags.wrapped_key =
                options.use_hw_wrapped_key = !options.use_hw_wrapped_key;
            retry = false;
            goto install;
        }
        return false;
    }
""",
    """    KeyBuffer device_key;
    if (!retrieveOrGenerateKey(GetDeviceKeyPath(), GetDeviceKeyTemp(), GetEmptyAuthentication(),
                               makeGen(options), &device_key))
        return false;

    EncryptionPolicy device_policy;
    if (!install_storage_key(DATA_MNT_POINT, options, device_key, &device_policy)) {
        LOG(ERROR) << "[H40 FSCRYPTMODE] system key install failed without mode fallback: wrapped="
                   << options.use_hw_wrapped_key;
        return false;
    }
    LOG(INFO) << "[H40 FSCRYPTMODE] system key installed without mode fallback: wrapped="
              << options.use_hw_wrapped_key;
""",
    "wrapped-key fallback removal",
)

for marker in (
    "[H40 FSCRYPTKEYRING] existing:",
    "[H40 FSCRYPTKEYRING] created:",
    "[H40 FSCRYPTKEYRING] ready before TWRP metadata decrypt",
    "[H40 FSCRYPTKEYRING] ready before setup_de_ce(0)",
):
    if marker not in adapter:
        raise SystemExit(f"V4.7 adapter marker missing after transform: {marker}")

for marker in (
    "[H40 FSCRYPTMODE] data options:",
    "[H40 FSCRYPTMODE] system key install failed without mode fallback:",
    "[H40 FSCRYPTMODE] system key installed without mode fallback:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.7 FsCrypt marker missing after transform: {marker}")

for forbidden in (
    "bool retry",
    "!retry",
    "Trying %s wrappedkey",
    "goto install",
    "install:\n",
    "fs_mgr_flags.wrapped_key =",
    "options.use_hw_wrapped_key = !options.use_hw_wrapped_key",
):
    if forbidden in fscrypt:
        raise SystemExit(f"V4.7 unsafe wrapped-key fallback survived: {forbidden}")

with adapter_path.open("w", newline="\n") as stream:
    stream.write(adapter)
with fscrypt_path.open("w", newline="\n") as stream:
    stream.write(fscrypt)

print("Applied H.40 V4.7 fscrypt session-keyring and key-mode fix")
print("  keyring: present before TWRP metadata/DE path and rechecked before OEM setup")
print("  mode: explicit encryption options retained; legacy v1 wrapped flag augmented")
print("  fallback: process-global raw/wrapped inversion removed")
