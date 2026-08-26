#!/usr/bin/env python3
from pathlib import Path
import shutil
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: apply-h40-v49-credential-helper.py RECOVERY_ROOT VOLD_ROOT"
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"V4.9 {label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter_path = recovery_root / "oplus_h40_decrypt.cpp"
android_mk_path = recovery_root / "Android.mk"
fscrypt_path = vold_root / "FsCrypt.cpp"
asset_root = Path(__file__).resolve().parent / "h40-v49"

adapter = adapter_path.read_text()
android_mk = android_mk_path.read_text()
fscrypt = fscrypt_path.read_text()

if "[H40 V49 HELPER]" in adapter or "oplus_h40_credential_client.cpp" in android_mk:
    raise SystemExit("V4.9 isolated-credential transform already applied")
for marker, source in (
    ("[H40 USERMAP]", adapter),
    ("[H40 FSCRYPTMODE]", fscrypt),
):
    if marker not in source:
        raise SystemExit(f"V4.9 requires the post-V4.8 source marker: {marker}")

adapter = replace_once(
    adapter,
    '#include "twcommon.h"\n',
    '#include "twcommon.h"\n#include "oplus_h40_credential_client.hpp"\n',
    "client include",
)
adapter = replace_once(
    adapter,
    '''constexpr char kVerifySymbol[] =
        "_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi";
''',
    "",
    "private verifier symbol",
)
adapter = replace_once(
    adapter,
    "using VerifyFn = int (*)(std::string, int);\n",
    "",
    "private verifier type",
)
adapter = replace_once(
    adapter,
    "    VerifyFn verify = nullptr;\n",
    "",
    "private verifier API member",
)
adapter = replace_once(
    adapter,
    "        loaded.verify = FindSymbol<VerifyFn>(loaded.handle, kVerifySymbol);\n",
    "",
    "private verifier dlsym",
)
adapter = replace_once(
    adapter,
    '''        if (loaded.verify == nullptr || loaded.setup_de_ce == nullptr ||
            loaded.get_password_type == nullptr || loaded.init_user0_ce == nullptr ||
''',
    '''        if (loaded.setup_de_ce == nullptr || loaded.get_password_type == nullptr ||
            loaded.init_user0_ce == nullptr ||
''',
    "private verifier load guard",
)

old_verify = '''    LOGINFO("Oplus H.40 invoking credential verify for user 0\\n");
    const int verify_result = api.verify(password, 0);
    LOGINFO("Oplus H.40 credential verify for user 0 returned %d\\n", verify_result);
    if (verify_result != 0) {
        // A wrong credential is authoritative for this attempt but retryable;
        // do not poison the process-lifetime setup state.
        return Result::kFailure;
    }

    // OplusCredentialVerify returns 0 after a successful gatekeeper response
    // even if its internal fscrypt_init_user0_ce() call fails. Repeating the
    // idempotent helper supplies the missing CE-key postcondition.
    LOGINFO("Oplus H.40 invoking user 0 CE postcondition\\n");
    state.user0_ce_ready = api.init_user0_ce();
    LOGINFO("Oplus H.40 user 0 CE postcondition returned %d\\n", state.user0_ce_ready);
    if (!state.user0_ce_ready) {
        return FailActive("CE postcondition failed after accepted credential");
    }
    if (!ValidateUser0CeLayout()) {
        return FailActive("CE paths are not accessible after accepted credential");
    }
'''
new_verify = '''    LOGINFO("[H40 V49 HELPER] launching stock-runtime credential verifier for user 0\\n");
    const IsolatedVerifyResult isolated_result =
            VerifyCredentialIsolated(password, state.user0.raw_password_type);
    if (isolated_result == IsolatedVerifyResult::kRejected) {
        // Only a normal OEM rejection is retryable. No automatic retry occurs.
        return Result::kFailure;
    }
    if (isolated_result != IsolatedVerifyResult::kAccepted) {
        return FailActive("isolated OEM credential verifier failed ambiguously");
    }

    // The helper owns credential-derived OEM state and exits only after its CE
    // initializer succeeds. Kernel fscrypt status is the cross-process proof;
    // never repeat the private-namespace CE helper in this process.
    state.user0_ce_ready = ValidateUser0CeLayout();
    if (!state.user0_ce_ready) {
        return FailActive("CE key/layout proof failed after isolated credential acceptance");
    }
'''
adapter = replace_once(adapter, old_verify, new_verify, "credential call boundary")

old_android_flag = '''    ifeq ($(TW_INCLUDE_OPLUS_H40_DECRYPT),true)
        LOCAL_SRC_FILES += oplus_h40_decrypt.cpp
        LOCAL_CFLAGS += -DTW_INCLUDE_OPLUS_H40_DECRYPT
        LOCAL_SHARED_LIBRARIES += libdl android.hardware.keymaster@4.0 libkeymaster4support
'''
new_android_flag = '''    ifeq ($(TW_INCLUDE_OPLUS_H40_DECRYPT),true)
        LOCAL_SRC_FILES += oplus_h40_decrypt.cpp oplus_h40_credential_client.cpp
        LOCAL_CFLAGS += -DTW_INCLUDE_OPLUS_H40_DECRYPT
        LOCAL_REQUIRED_MODULES += oplus_h40_credential_helper
        LOCAL_SHARED_LIBRARIES += libdl android.hardware.keymaster@4.0 libkeymaster4support
'''
android_mk = replace_once(
    android_mk, old_android_flag, new_android_flag, "recovery client sources"
)

helper_module = '''include $(BUILD_EXECUTABLE)

ifeq ($(TW_INCLUDE_OPLUS_H40_DECRYPT),true)
# H.40 V4.9 credential verifier. This executable intentionally retains the
# stock /system/bin linker namespace; hybrid repacking must not relocate it.
include $(CLEAR_VARS)
LOCAL_MODULE := oplus_h40_credential_helper
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := oplus_h40_credential_helper.cpp
LOCAL_MULTILIB := 64
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/bin
LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils
LOCAL_CPPFLAGS := -Wall -Wextra -Werror -fno-exceptions -fno-rtti
LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)
endif

# Symlink for file_contexts
'''
android_mk = replace_once(
    android_mk,
    "include $(BUILD_EXECUTABLE)\n\n# Symlink for file_contexts\n",
    helper_module,
    "standalone helper module",
)

assets = (
    "oplus_h40_credential_protocol.hpp",
    "oplus_h40_credential_client.hpp",
    "oplus_h40_credential_client.cpp",
    "oplus_h40_credential_helper.cpp",
)
for name in assets:
    source = asset_root / name
    destination = recovery_root / name
    if not source.is_file():
        raise SystemExit(f"V4.9 source asset missing: {source}")
    if destination.exists():
        raise SystemExit(f"V4.9 refuses to overwrite existing source: {destination}")

for forbidden in (
    "kVerifySymbol",
    "using VerifyFn =",
    "VerifyFn verify",
    "loaded.verify",
    "api.verify(",
):
    if forbidden in adapter:
        raise SystemExit(f"V4.9 in-process verifier survived: {forbidden}")
for required in (
    '#include "oplus_h40_credential_client.hpp"',
    "VerifyCredentialIsolated(password, state.user0.raw_password_type)",
    "IsolatedVerifyResult::kRejected",
    "isolated OEM credential verifier failed ambiguously",
    "ValidateUser0CeLayout()",
):
    if required not in adapter:
        raise SystemExit(f"V4.9 adapter contract missing: {required}")
for required in (
    "oplus_h40_decrypt.cpp oplus_h40_credential_client.cpp",
    "LOCAL_REQUIRED_MODULES += oplus_h40_credential_helper",
    "LOCAL_MODULE := oplus_h40_credential_helper",
    "LOCAL_MULTILIB := 64",
    "LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/bin",
    "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils",
):
    if required not in android_mk:
        raise SystemExit(f"V4.9 Android.mk contract missing: {required}")

# Defer filesystem changes until every source and transformation contract has
# passed, so a validation failure leaves the input tree rerunnable.
for name in assets:
    shutil.copyfile(asset_root / name, recovery_root / name)
with adapter_path.open("w", newline="\n") as stream:
    stream.write(adapter)
with android_mk_path.open("w", newline="\n") as stream:
    stream.write(android_mk)

print("Applied H.40 V4.9 isolated credential verifier")
print("  namespace: helper remains /system/bin with stock H.40 runtime")
print("  transport: SOCK_SEQPACKET protocol; credential absent from argv/env/files")
print("  crash: async-signal-safe AArch64 register packet preserves recovery UI")
print("  success: normal helper exit plus parent fscrypt CE policy/key proof")
