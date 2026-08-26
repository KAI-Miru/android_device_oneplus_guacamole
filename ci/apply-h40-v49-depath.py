#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v49-depath.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
steps = [
    ("V4.8 validated DE-path base", repo_root / "ci" / "apply-h40-v48-depath.py"),
    (
        "V4.9 isolated stock-runtime credential verifier",
        repo_root / "ci" / "apply-h40-v49-credential-helper.py",
    ),
]
for label, script in steps:
    if not script.is_file():
        raise SystemExit(f"{label} transform missing: {script}")
    subprocess.run([sys.executable, str(script), sys.argv[1], sys.argv[2]], check=True)

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter = (recovery_root / "oplus_h40_decrypt.cpp").read_text()
client = (recovery_root / "oplus_h40_credential_client.cpp").read_text()
helper = (recovery_root / "oplus_h40_credential_helper.cpp").read_text()
protocol = (recovery_root / "oplus_h40_credential_protocol.hpp").read_text()
android_mk = (recovery_root / "Android.mk").read_text()
fscrypt = (vold_root / "FsCrypt.cpp").read_text()

for forbidden in (
    "kVerifySymbol",
    "using VerifyFn =",
    "VerifyFn verify",
    "loaded.verify",
    "api.verify(",
):
    if forbidden in adapter:
        raise SystemExit(f"V4.9 in-process OEM verifier survived: {forbidden}")

for required in (
    "VerifyCredentialIsolated(password, state.user0.raw_password_type)",
    "IsolatedVerifyResult::kRejected",
    "isolated OEM credential verifier failed ambiguously",
    "CE key/layout proof failed after isolated credential acceptance",
):
    if required not in adapter:
        raise SystemExit(f"V4.9 adapter boundary missing: {required}")

for required in (
    "socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC",
    "posix_spawn_file_actions_adddup2",
    "POSIX_SPAWN_SETSIGMASK",
    "SaveHelperMaps",
    "SaveCrashReport",
    "SecureWipe(credential_packet.data()",
    "close(spawned_socket.release())",
    "KillAndReap",
):
    if required not in client:
        raise SystemExit(f"V4.9 client contract missing: {required}")
for forbidden in ("system(", "fork(", "popen(", "LD_LIBRARY_PATH", "credential.c_str()"):
    if forbidden in client:
        raise SystemExit(f"V4.9 unsafe client mechanism present: {forbidden}")
if "explicit_bzero(" in client or "explicit_bzero(" in helper:
    raise SystemExit("V4.9 Android 12L-incompatible explicit_bzero survived")

for required in (
    'kOemLibraryPath[] = "/system/lib64/libdecrypt_recovery.so"',
    "keyctl_search(KEY_SPEC_SESSION_KEYRING",
    "setup_de_ce(0)",
    "get_password_type(0)",
    "verify(std::move(credential), 0)",
    "init_user0_ce()",
    "SA_SIGINFO | SA_ONSTACK | SA_RESETHAND",
    "sigfillset(&action.sa_mask)",
    "__atomic_always_lock_free(sizeof(std::uint64_t)",
    "LoadAttemptId()",
    "context->uc_mcontext.regs[index]",
    "context->uc_mcontext.pc",
    "write(protocol::kProtocolFd, &crash, sizeof(crash))",
    "SecureWipe(packet.data(), packet.size())",
):
    if required not in helper and required not in protocol:
        raise SystemExit(f"V4.9 helper contract missing: {required}")

for required in (
    "sizeof(CrashFrame) == 328",
    "kMaxCredentialBytes = 1024",
    "kProtocolFd = 3",
    "HeaderMatches",
):
    if required not in protocol:
        raise SystemExit(f"V4.9 protocol contract missing: {required}")

for required in (
    "LOCAL_REQUIRED_MODULES += oplus_h40_credential_helper",
    "LOCAL_MODULE := oplus_h40_credential_helper",
    "LOCAL_MULTILIB := 64",
    "LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/bin",
    "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils",
):
    if required not in android_mk:
        raise SystemExit(f"V4.9 build contract missing: {required}")

for marker in (
    "[H40 USERMAP]",
    "[H40 FSCRYPTKEYRING]",
):
    if marker not in adapter:
        raise SystemExit(f"V4.9 lost inherited adapter marker: {marker}")
for marker in (
    "[H40 FSCRYPTMODE]",
    "[H40 FSCRYPTLAZY]",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.9 lost inherited FsCrypt marker: {marker}")

print("Applied H.40 V4.9 DE-path compatibility stack")
print("  inherited: V4.8 user0-only secondary-profile coexistence")
print("  verifier: stock-runtime exec helper; no private-process Gatekeeper call")
print("  crash containment: fixed AArch64 register packet; recovery stays alive")
print("  authorization: only normal OEM rejection retries; ambiguity is fatal")
