#!/usr/bin/env python3
from pathlib import Path
import shutil
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: apply-h40-v50-modern-keystorage.py RECOVERY_ROOT VOLD_ROOT"
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"V5.0 {label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter_path = recovery_root / "oplus_h40_decrypt.cpp"
adapter_header_path = recovery_root / "oplus_h40_decrypt.hpp"
partitionmanager_path = recovery_root / "partitionmanager.cpp"
android_mk_path = recovery_root / "Android.mk"
fscrypt_path = vold_root / "FsCrypt.cpp"
key_storage_path = vold_root / "KeyStorage.cpp"
keymaster_path = vold_root / "Keymaster.cpp"
decrypt_path = vold_root / "Decrypt.cpp"
repo_ci = Path(__file__).resolve().parent
old_asset_root = repo_ci / "h40-v49"
asset_root = repo_ci / "h40-v50"

adapter = adapter_path.read_text()
adapter_header = adapter_header_path.read_text()
partitionmanager = partitionmanager_path.read_text()
android_mk = android_mk_path.read_text()
fscrypt = fscrypt_path.read_text()
key_storage = key_storage_path.read_text()
keymaster = keymaster_path.read_text()
decrypt = decrypt_path.read_text()

if "[H40 V50 HANDOFF]" in adapter:
    raise SystemExit("V5.0 modern-keystorage transform already applied")
for marker, source in (
    ("[H40 V49 HELPER]", adapter),
    ("[H40 FSCRYPTMODE]", fscrypt),
    ("malformed pKMblob prefix", keymaster),
):
    if marker not in source:
        raise SystemExit(f"V5.0 requires inherited source marker: {marker}")

assets = (
    "oplus_h40_credential_protocol.hpp",
    "oplus_h40_credential_client.hpp",
    "oplus_h40_credential_client.cpp",
    "oplus_h40_credential_helper.cpp",
)
for name in assets:
    inherited = old_asset_root / name
    destination = recovery_root / name
    replacement = asset_root / name
    if not inherited.is_file() or not replacement.is_file():
        raise SystemExit(f"V5.0 source asset missing: {name}")
    if not destination.is_file() or destination.read_bytes() != inherited.read_bytes():
        raise SystemExit(f"V5.0 refuses noncanonical inherited asset: {destination}")

adapter_header = replace_once(
    adapter_header,
    '''// Unavailable is possible only before the OEM implementation has performed
// any side effect. Once selected, every refusal or runtime failure is
// authoritative and callers must not fall through to another decrypt stack.
''',
    '''// Unavailable is possible only before the OEM implementation has performed
// any side effect. kModernHandoff is the sole explicit transition into TeamWin
// decryption, and is returned only after the isolated OEM gate accepts the
// credential. kRejected is the only retryable outcome; kFatalFailure latches
// every ambiguous or infrastructure failure for the recovery process lifetime.
''',
    "public handoff documentation",
)
adapter_header = replace_once(
    adapter_header,
    '''enum class Result {
    kUnavailable,
    kFailure,
    kSuccess,
};
''',
    '''enum class Result {
    kUnavailable,
    kRejected,
    kFatalFailure,
    kModernHandoff,
    kSuccess,
};
''',
    "public result state",
)
adapter_header = replace_once(
    adapter_header,
    '''Result DecryptUser(const std::string& password, int user_id);
''',
    '''Result DecryptUser(const std::string& password, int user_id);
Result CompleteModernHandoff(bool decrypt_succeeded);
''',
    "handoff completion declaration",
)

adapter = replace_once(
    adapter,
    '''Result FailActive(const char* reason) {
    RuntimeState& state = GetRuntimeState();
    state.phase = Phase::kFatal;
    LOGERR("Oplus H.40 v4 hybrid adapter entered process-lifetime fatal state: %s\\n", reason);
    return Result::kFailure;
}
''',
    '''Result FailActive(const char* reason) {
    RuntimeState& state = GetRuntimeState();
    state.phase = Phase::kFatal;
    LOGERR("Oplus H.40 v5 hybrid adapter entered process-lifetime fatal state: %s\\n", reason);
    return Result::kFatalFailure;
}
''',
    "fatal result classification",
)

adapter = replace_once(
    adapter,
    '''#include <android/hidl/base/1.0/IBase.h>
''',
    '''#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <android/hidl/base/1.0/IBase.h>
''',
    "authorization Binder headers",
)
adapter = replace_once(
    adapter,
    '''    kPreparedNoLock,
    kUnlocked,
    kFatal,
''',
    '''    kPreparedNoLock,
    kAwaitingModernHandoff,
    kUnlocked,
    kFatal,
''',
    "runtime handoff phase",
)
adapter = replace_once(
    adapter,
    '''    if (state.phase == Phase::kFatal || state.phase == Phase::kActive ||
        state.phase == Phase::kUnlocked) {
        return Result::kFailure;
    }
''',
    '''    if (state.phase == Phase::kFatal) return Result::kFatalFailure;
    if (state.phase == Phase::kActive ||
        state.phase == Phase::kAwaitingModernHandoff ||
        state.phase == Phase::kUnlocked) {
        return FailActive("credential request arrived in an invalid adapter phase");
    }
''',
    "credential phase guard",
)
adapter = replace_once(
    adapter,
    '''constexpr const char* kCredentialHalServices[] = {
        "vendor.gatekeeper-1-0",
};
''',
    '''constexpr const char* kCredentialServices[] = {
        "vendor.gatekeeper-1-0",
        "keystore2",
};
constexpr char kAuthorizationService[] = "android.security.authorization";
''',
    "modern credential service contract",
)
adapter = replace_once(
    adapter,
    '''    // The H.40 implementation always calls fscrypt_init_user0_ce(), even when
    // its integer argument is nonzero. Once OEM setup is active, a secondary
    // user is an authoritative refusal, never a generic-fallback opportunity.
''',
    '''    // The stock H.40 ABI is hard-wired to user 0, and the exact verifier
    // patch plus modern handoff is validated only for that user. A secondary
    // user remains an authoritative refusal, never a generic fallback.
''',
    "user0-only rationale",
)
adapter = replace_once(
    adapter,
    '''bool PrepareCredentialServices() {
    if (!GetRuntimeState().data_mapped) {
        LOGERR("Oplus H.40 decrypt: refusing to start gatekeeper before mapped /data\\n");
        return false;
    }
    if (!SetProperty("ctl.start", "vendor.gatekeeper-1-0")) return false;
    // The OEM verifier talks directly to the vendor gatekeeper HIDL HAL.
    // gatekeeperd is useful to the surrounding recovery, but its /data working
    // directory must not make the direct OEM credential call fail.
    SetProperty("ctl.start", "gatekeeperd");
    return WaitForRunningServices(kCredentialHalServices, "credential HAL");
}
''',
    '''bool WaitForAuthorizationEndpoint() {
    int stable_polls = 0;
    for (int poll = 0; poll < kServiceWaitPolls; ++poll) {
        ::ndk::SpAIBinder service(AServiceManager_checkService(kAuthorizationService));
        if (service.get() != nullptr) {
            if (++stable_polls >= kStableServicePolls) {
                LOGINFO("[H40 V50 HANDOFF] %s ready after %d stable samples\\n",
                        kAuthorizationService, kStableServicePolls);
                return true;
            }
        } else {
            stable_polls = 0;
        }
        usleep(kServicePollIntervalUs);
    }
    LOGERR("[H40 V50 HANDOFF] timed out waiting for %s\\n", kAuthorizationService);
    return false;
}

bool PrepareCredentialServices() {
    if (!GetRuntimeState().data_mapped) {
        LOGERR("Oplus H.40 decrypt: refusing to start credential services before mapped /data\\n");
        return false;
    }
    if (!SetProperty("ctl.start", "vendor.gatekeeper-1-0")) return false;
    if (!SetProperty("ctl.start", "keystore2")) return false;
    // The isolated OEM verifier uses the HIDL HAL. TeamWin's modern SP unwrap
    // also publishes the resulting auth token through KeystoreAuthorization.
    SetProperty("ctl.start", "gatekeeperd");
    if (!WaitForRunningServices(kCredentialServices, "credential services")) return false;
    return WaitForAuthorizationEndpoint();
}
''',
    "keystore2 authorization readiness",
)
adapter = replace_once(
    adapter,
    '''    if (user_id != 0) {
        LOGERR("Oplus H.40 user0-only mode refusing credential for user %d\\n", user_id);
        return Result::kFailure;
    }
''',
    '''    if (user_id != 0) {
        LOGERR("Oplus H.40 user0-only mode refusing credential for user %d\\n", user_id);
        return FailActive("credential request targeted an unsupported user");
    }
''',
    "unsupported-user fatal classification",
)
adapter = replace_once(
    adapter,
    '''        if (!state.user0.no_credential) {
            LOGERR("Oplus H.40 decrypt: refusing no-lock probe for credentialed user 0\\n");
            return Result::kFailure;
        }
''',
    '''        if (!state.user0.no_credential) {
            LOGERR("Oplus H.40 decrypt: refusing no-lock probe for credentialed user 0\\n");
            return FailActive("no-lock credential used for a locked user");
        }
''',
    "invalid no-lock probe classification",
)
adapter = replace_once(
    adapter,
    '''    if (state.user0.no_credential) {
        LOGERR("Oplus H.40 decrypt: refusing credential verify for no-lock user 0\\n");
        return Result::kFailure;
    }
    if (!PrepareCredentialServices()) return Result::kFailure;
''',
    '''    if (state.user0.no_credential) {
        LOGERR("Oplus H.40 decrypt: refusing credential verify for no-lock user 0\\n");
        return FailActive("credential supplied for a no-lock user");
    }
    if (!PrepareCredentialServices()) {
        return FailActive("credential services unavailable before isolated verifier");
    }
''',
    "credential infrastructure fatal classification",
)

old_credential_tail = '''    LOGINFO("[H40 V49 HELPER] launching stock-runtime credential verifier for user 0\\n");
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
    state.phase = Phase::kUnlocked;
    LOGINFO("Oplus H.40 v3 user 0 CE postcondition satisfied\\n");
    return Result::kSuccess;
}
'''
new_credential_tail = '''    LOGINFO("[H40 V50 HANDOFF] launching exact-H.40 isolated credential gate for user 0\\n");
    const IsolatedVerifyResult isolated_result =
            VerifyCredentialIsolated(password, state.user0.raw_password_type);
    if (isolated_result == IsolatedVerifyResult::kRejected) {
        // OEM -1/non-acceptance is retryable. The modern path is never called
        // for a non-accepted credential, avoiding a second Gatekeeper attempt.
        return Result::kRejected;
    }
    if (isolated_result != IsolatedVerifyResult::kAccepted) {
        return FailActive("isolated OEM credential gate failed ambiguously");
    }

    // The exact-hash helper suppresses the OEM Android-10 empty-auth CE init.
    // Keep the adapter locked until TeamWin derives the real synthetic-password
    // secret and the fscrypt key/policy proof succeeds.
    state.phase = Phase::kAwaitingModernHandoff;
    LOGINFO("[H40 V50 HANDOFF] OEM credential accepted; requesting modern SP unwrap\\n");
    return Result::kModernHandoff;
}

Result CompleteModernHandoff(bool decrypt_succeeded) {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    RuntimeState& state = GetRuntimeState();
    if (state.phase != Phase::kAwaitingModernHandoff) {
        return FailActive("modern decryption completion arrived in an invalid phase");
    }
    if (!decrypt_succeeded) {
        return FailActive("modern synthetic-password handoff failed after OEM acceptance");
    }
    state.user0_ce_ready = ValidateUser0CeLayout();
    if (!state.user0_ce_ready) {
        return FailActive("modern handoff returned without CE key/layout proof");
    }
    state.phase = Phase::kUnlocked;
    LOGINFO("[H40 V50 HANDOFF] modern user 0 CE postcondition satisfied\\n");
    return Result::kSuccess;
}
'''
adapter = replace_once(
    adapter, old_credential_tail, new_credential_tail, "credential handoff boundary"
)
if adapter.count("return Result::kFailure;") != 3:
    raise SystemExit(
        "V5.0 residual fatal result classification: expected three source matches"
    )
adapter = adapter.replace("return Result::kFailure;", "return Result::kFatalFailure;")

decrypt = replace_once(
    decrypt,
    '''\t\t\tandroid::hardware::hidl_vec<uint8_t> gk_pwd_token_hidl;
\t\t\tGKResponse gkResponse;
\t\t\tgk_pwd_token_hidl.setToExternal(const_cast<uint8_t *>((const uint8_t *)gk_pwd_token), SHA512_DIGEST_LENGTH);
\t\t\tandroid::hardware::Return<void> hwRet =
''',
    '''\t\t\tandroid::hardware::hidl_vec<uint8_t> gk_pwd_token_hidl;
\t\t\tGKResponse gkResponse;
\t\t\tbool authorization_failed = false;
\t\t\tgk_pwd_token_hidl.setToExternal(const_cast<uint8_t *>((const uint8_t *)gk_pwd_token), SHA512_DIGEST_LENGTH);
\t\t\tandroid::hardware::Return<void> hwRet =
''',
    "authorization failure state",
)
decrypt = replace_once(
    decrypt,
    '''\t\t\t\t\t\t\t\t  [&gkResponse]
''',
    '''\t\t\t\t\t\t\t\t  [&gkResponse, &authorization_failed]
''',
    "authorization failure capture",
)
decrypt = replace_once(
    decrypt,
    '''\t\t\t\t\t\t\t\t\t\t\tif (service == NULL) {
\t\t\t\t\t\t\t\t\t\t\t\tprintf("error: could not connect to keystore service\\n");
\t\t\t\t\t\t\t\t\t\t\t\tALOGE("error: could not connect to keystore service\\n");
\t\t\t\t\t\t\t\t\t\t\t}
\t\t\t\t\t\t\t\t\t\t\tauto binder_result = service->addAuthToken(authToken);
''',
    '''\t\t\t\t\t\t\t\t\t\t\tif (service == NULL) {
\t\t\t\t\t\t\t\t\t\t\t\tprintf("error: could not connect to keystore authorization service\\n");
\t\t\t\t\t\t\t\t\t\t\t\tALOGE("error: could not connect to keystore authorization service\\n");
\t\t\t\t\t\t\t\t\t\t\t\tauthorization_failed = true;
\t\t\t\t\t\t\t\t\t\t\t\treturn;
\t\t\t\t\t\t\t\t\t\t\t}
\t\t\t\t\t\t\t\t\t\t\tauto binder_result = service->addAuthToken(authToken);
\t\t\t\t\t\t\t\t\t\t\tif (!binder_result.isOk()) {
\t\t\t\t\t\t\t\t\t\t\t\tALOGE("error: could not publish Gatekeeper auth token\\n");
\t\t\t\t\t\t\t\t\t\t\t\tauthorization_failed = true;
\t\t\t\t\t\t\t\t\t\t\t}
''',
    "authorization null and transaction guard",
)
decrypt = replace_once(
    decrypt,
    '''\t\t\tif (!hwRet.isOk()) {
\t\t\t\tprintf("gatekeeper verification failed\\n");
\t\t\t\treturn Free_Return(retval, weaver_key, &pwd);
\t\t\t}
''',
    '''\t\t\tif (!hwRet.isOk() || authorization_failed) {
\t\t\t\tprintf("gatekeeper verification or auth-token publication failed\\n");
\t\t\t\treturn Free_Return(retval, weaver_key, &pwd);
\t\t\t}
''',
    "authorization fail-closed return",
)

partitionmanager = replace_once(
    partitionmanager,
    "#include <sys/wait.h>\n",
    "#include <sys/wait.h>\n#include <sys/prctl.h>\n#include <signal.h>\n",
    "isolated modern decrypt headers",
)

partitionmanager = replace_once(
    partitionmanager,
    '''namespace {
bool g_oplus_h40_decrypt_blocked = false;

bool IsOplusMapperMountedAtData(const std::string& mapper) {
''',
    '''namespace {
bool g_oplus_h40_decrypt_blocked = false;

enum class ModernDecryptResult {
	kSuccess,
	kFailure,
	kFatalFailure,
};

ModernDecryptResult RunModernDecryptIsolated(int user_id, const std::string& password) {
	const pid_t pid = fork();
	if (pid < 0) {
		LOGERR("[H40 V50 HANDOFF] failed to fork modern decrypt worker: %s\\n", strerror(errno));
		return ModernDecryptResult::kFatalFailure;
	}
	if (pid == 0) {
		// Decrypt_User is existing TeamWin code. Run it in a disposable child so
		// malformed SP/Keymaster input cannot terminate the recovery UI process.
		if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1 ||
			prctl(PR_SET_DUMPABLE, 0) != 0) {
			_exit(2);
		}
		const bool decrypted = android::keystore::Decrypt_User(user_id, password);
		_exit(decrypted ? 0 : 1);
	}

	// TeamWin already uses this bounded child-wait primitive for legacy
	// decryption. A timeout, signal, wait error, or unknown exit code is fatal.
	int status = 0x7f;
	if (TWFunc::Wait_For_Child_Timeout(pid, &status, "H40 modern decrypt", 120) != 0 ||
		!WIFEXITED(status)) {
		return ModernDecryptResult::kFatalFailure;
	}
	if (WEXITSTATUS(status) == 0) return ModernDecryptResult::kSuccess;
	if (WEXITSTATUS(status) == 1) return ModernDecryptResult::kFailure;
	return ModernDecryptResult::kFatalFailure;
}

bool IsOplusMapperMountedAtData(const std::string& mapper) {
''',
    "isolated modern decrypt worker",
)

partitionmanager = replace_once(
    partitionmanager,
    '''\t\t\t} else if (oplus_runtime == twrp::oplus_h40::Result::kFailure) {
\t\t\t\tg_oplus_h40_decrypt_blocked = true;
''',
    '''\t\t\t} else if (oplus_runtime == twrp::oplus_h40::Result::kFatalFailure) {
\t\t\t\tg_oplus_h40_decrypt_blocked = true;
''',
    "metadata fatal result latch",
)

old_dispatch = '''		bool decrypt_success = false;
		bool try_generic_decrypt = true;
		const twrp::oplus_h40::Result oplus_result =
			twrp::oplus_h40::DecryptUser(Password, user_id);
		if (oplus_result == twrp::oplus_h40::Result::kSuccess) {
			decrypt_success = true;
			try_generic_decrypt = false;
		} else if (oplus_result == twrp::oplus_h40::Result::kFailure) {
			// Avoid a second gatekeeper attempt and unintended rate limiting.
			try_generic_decrypt = false;
		} else if (oplus_active) {
			// Defense in depth: Unavailable is legal only before activation.
			// Never enter TeamWin vold after this process selected OEM state.
			try_generic_decrypt = false;
			g_oplus_h40_decrypt_blocked = true;
			LOGERR("Oplus H.40 active adapter returned unavailable; refusing generic credential fallback\\n");
		}
		if (try_generic_decrypt) {
			decrypt_success = android::keystore::Decrypt_User(user_id, Password);
		}
'''
new_dispatch = '''		bool decrypt_success = false;
		bool try_generic_decrypt = true;
		const twrp::oplus_h40::Result oplus_result =
			twrp::oplus_h40::DecryptUser(Password, user_id);
		if (oplus_result == twrp::oplus_h40::Result::kSuccess) {
			decrypt_success = true;
			try_generic_decrypt = false;
		} else if (oplus_result == twrp::oplus_h40::Result::kModernHandoff) {
			try_generic_decrypt = false;
			LOGINFO("[H40 V50 HANDOFF] deriving the accepted user 0 credential in an isolated TeamWin SP worker\\n");
			const ModernDecryptResult modern_result =
				RunModernDecryptIsolated(user_id, Password);
			const bool modern_decrypt = modern_result == ModernDecryptResult::kSuccess;
			decrypt_success = twrp::oplus_h40::CompleteModernHandoff(modern_decrypt) ==
				twrp::oplus_h40::Result::kSuccess;
			if (!decrypt_success) {
				g_oplus_h40_decrypt_blocked = true;
			}
		} else if (oplus_result == twrp::oplus_h40::Result::kRejected) {
			// Avoid a second Gatekeeper attempt for a rejected credential.
			try_generic_decrypt = false;
		} else if (oplus_result == twrp::oplus_h40::Result::kFatalFailure) {
			// Infrastructure and ambiguous adapter failures are process-lifetime
			// fatal. Never present them as a retryable wrong credential.
			try_generic_decrypt = false;
			g_oplus_h40_decrypt_blocked = true;
		} else if (oplus_active) {
			// Defense in depth: Unavailable is legal only before activation.
			try_generic_decrypt = false;
			g_oplus_h40_decrypt_blocked = true;
			LOGERR("Oplus H.40 active adapter returned unavailable; refusing generic credential fallback\\n");
		}
		if (try_generic_decrypt) {
			decrypt_success = android::keystore::Decrypt_User(user_id, Password);
		}
'''
partitionmanager = replace_once(
    partitionmanager, old_dispatch, new_dispatch, "partition-manager handoff"
)
partitionmanager = replace_once(
    partitionmanager,
    '''				if (oplus_result == twrp::oplus_h40::Result::kSuccess) {
''',
    '''				if (oplus_result == twrp::oplus_h40::Result::kSuccess ||
					oplus_result == twrp::oplus_h40::Result::kModernHandoff) {
''',
    "secondary-user suppression",
)

android_mk = replace_once(
    android_mk,
    "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils\n",
    "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils libcrypto\n",
    "helper SHA-256 dependency",
)
android_mk = replace_once(
    android_mk,
    "# H.40 V4.9 credential verifier. This executable intentionally retains the\n",
    "# H.40 V5.0 exact credential gate. This executable intentionally retains the\n",
    "helper version marker",
)

for forbidden in (
    "kCeInitialized",
    "kCeAttemptCompleted",
    "context->uc_mcontext.regs[index]",
    "crash.registers",
    "crash.stack_pointer",
    "crash.fault_address",
):
    for name, source in (
        ("adapter", adapter),
        ("client", (asset_root / "oplus_h40_credential_client.cpp").read_text()),
        ("helper", (asset_root / "oplus_h40_credential_helper.cpp").read_text()),
        ("protocol", (asset_root / "oplus_h40_credential_protocol.hpp").read_text()),
    ):
        if forbidden in source:
            raise SystemExit(f"V5.0 forbidden {name} mechanism survived: {forbidden}")
if "init_user0_ce()" in (asset_root / "oplus_h40_credential_helper.cpp").read_text():
    raise SystemExit("V5.0 helper still invokes the legacy CE initializer")

for required in (
    "Result::kModernHandoff",
    "Result::kRejected",
    "Result::kFatalFailure",
    "Phase::kAwaitingModernHandoff",
    "CompleteModernHandoff(bool decrypt_succeeded)",
    "modern synthetic-password handoff failed after OEM acceptance",
    "ValidateUser0CeLayout()",
    "WaitForAuthorizationEndpoint()",
    'SetProperty("ctl.start", "keystore2")',
    "AServiceManager_checkService(kAuthorizationService)",
):
    if required not in adapter and required not in adapter_header:
        raise SystemExit(f"V5.0 adapter contract missing: {required}")
for required in (
    "RunModernDecryptIsolated(user_id, Password)",
    "CompleteModernHandoff(modern_decrypt)",
    "Result::kModernHandoff",
    "Result::kRejected",
    "Result::kFatalFailure",
    "PR_SET_DUMPABLE",
    "Wait_For_Child_Timeout",
):
    if required not in partitionmanager:
        raise SystemExit(f"V5.0 dispatch contract missing: {required}")
for required in (
    "bool authorization_failed = false;",
    "authorization_failed = true;",
    "if (!hwRet.isOk() || authorization_failed)",
    "if (!binder_result.isOk())",
):
    if required not in decrypt:
        raise SystemExit(f"V5.0 TeamWin authorization guard missing: {required}")
if '''if (service == NULL) {
\t\t\t\t\t\t\t\t\t\t\t\tprintf("error: could not connect to keystore service\\n");
''' in decrypt:
    raise SystemExit("V5.0 unguarded KeystoreAuthorization null branch survived")
for required in (
    "VerifyOemFileIdentity()",
    "kExpectedOemSha256",
    "kCredentialLogCallInstruction",
    "kLegacyCeInitCallInstruction",
    "kAarch64MovW0One",
    "VerifierOpcodeContextMatches",
    "CloseInheritedFileDescriptors",
    "SecureWipeString(&credential)",
    "PR_SET_DUMPABLE",
    "verify_result == -1",
    "Stage::kCredentialAccepted",
):
    if required not in (asset_root / "oplus_h40_credential_helper.cpp").read_text():
        raise SystemExit(f"V5.0 helper contract missing: {required}")
for required in (
    "sizeof(CrashFrame) == 64",
    "sizeof(ReplyFrame) == 40",
    "kUnexpectedVerifyResult",
    "program_counter_offset",
    "link_register_offset",
    "address_flags",
):
    if required not in (asset_root / "oplus_h40_credential_protocol.hpp").read_text():
        raise SystemExit(f"V5.0 protocol contract missing: {required}")
if "oem_load_base" in (asset_root / "oplus_h40_credential_protocol.hpp").read_text():
    raise SystemExit("V5.0 protocol still exposes a raw OEM ASLR base")
if "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils libcrypto" not in android_mk:
    raise SystemExit("V5.0 helper libcrypto dependency missing")
if "# H.40 V5.0 exact credential gate." not in android_mk:
    raise SystemExit("V5.0 helper version marker missing")

# Defer all writes until the complete inherited-source and V5.0 contract pass.
for name in assets:
    shutil.copyfile(asset_root / name, recovery_root / name)
with adapter_path.open("w", newline="\n") as stream:
    stream.write(adapter)
with adapter_header_path.open("w", newline="\n") as stream:
    stream.write(adapter_header)
with partitionmanager_path.open("w", newline="\n") as stream:
    stream.write(partitionmanager)
with android_mk_path.open("w", newline="\n") as stream:
    stream.write(android_mk)
with decrypt_path.open("w", newline="\n") as stream:
    stream.write(decrypt)

print("Applied H.40 V5.0 exact credential gate and modern-keystorage handoff")
print("  verifier: exact stock SHA/symbol/opcode provenance; OEM PIN log suppressed")
print("  legacy CE init: skipped inside the isolated helper")
print("  keystore2: running plus KeystoreAuthorization endpoint required")
print("  modern CE: TeamWin synthetic-password unwrap, followed by fscrypt proof")
print("  isolation: TeamWin SP unwrap runs in a bounded disposable child")
print("  OEM -1/non-acceptance: retryable; fatal infrastructure failures latch")
