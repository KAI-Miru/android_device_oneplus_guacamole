#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v50-depath.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
steps = [
    ("V4.9 isolated credential base", repo_root / "ci" / "apply-h40-v49-depath.py"),
    (
        "V5.0 exact credential gate and modern-keystorage handoff",
        repo_root / "ci" / "apply-h40-v50-modern-keystorage.py",
    ),
]
for label, script in steps:
    if not script.is_file():
        raise SystemExit(f"{label} transform missing: {script}")
    subprocess.run([sys.executable, str(script), sys.argv[1], sys.argv[2]], check=True)

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter = (recovery_root / "oplus_h40_decrypt.cpp").read_text()
adapter_header = (recovery_root / "oplus_h40_decrypt.hpp").read_text()
partitionmanager = (recovery_root / "partitionmanager.cpp").read_text()
client = (recovery_root / "oplus_h40_credential_client.cpp").read_text()
helper = (recovery_root / "oplus_h40_credential_helper.cpp").read_text()
protocol = (recovery_root / "oplus_h40_credential_protocol.hpp").read_text()
android_mk = (recovery_root / "Android.mk").read_text()
fscrypt = (vold_root / "FsCrypt.cpp").read_text()
key_storage = (vold_root / "KeyStorage.cpp").read_text()
keymaster = (vold_root / "Keymaster.cpp").read_text()
decrypt = (vold_root / "Decrypt.cpp").read_text()

for required in (
    "[H40 V50 HANDOFF]",
    "Result::kModernHandoff",
    "Result::kRejected",
    "Result::kFatalFailure",
    "CompleteModernHandoff(bool decrypt_succeeded)",
    "ValidateUser0CeLayout()",
    "WaitForAuthorizationEndpoint()",
    'SetProperty("ctl.start", "keystore2")',
):
    if required not in adapter and required not in adapter_header:
        raise SystemExit(f"V5.0 adapter boundary missing: {required}")
for required in (
    "CompleteModernHandoff(modern_decrypt)",
    "android::keystore::Decrypt_User(user_id, Password)",
    "RunModernDecryptIsolated(user_id, Password)",
    "Wait_For_Child_Timeout",
):
    if required not in partitionmanager:
        raise SystemExit(f"V5.0 dispatch boundary missing: {required}")
for required in (
    "CaptureHelperMaps",
    "stockLibcrypto",
    "SecureWipe(credential_packet.data()",
    "reply.result == -1",
):
    if required not in client:
        raise SystemExit(f"V5.0 parent-side safety contract missing: {required}")
for required in (
    "VerifyOemFileIdentity()",
    "SymbolHasExpectedOrigin",
    "ApplyVerifierPatches",
    "VerifierOpcodeContextMatches",
    "CloseInheritedFileDescriptors",
    "SecureWipeString(&credential)",
    "kAarch64Nop",
    "kAarch64MovW0One",
    "PR_SET_PDEATHSIG",
    "PR_SET_DUMPABLE",
    "verify_result == -1",
):
    if required not in helper:
        raise SystemExit(f"V5.0 helper safety contract missing: {required}")
for forbidden in (
    "kInitUser0CeSymbol",
    "InitUser0CeFn",
    "init_user0_ce()",
    "registers[31]",
    "stack_pointer",
    "fault_address",
    "processor_state",
):
    if forbidden in helper or forbidden in protocol:
        raise SystemExit(f"V5.0 unsafe helper mechanism survived: {forbidden}")
for required in (
    "sizeof(ReplyFrame) == 40",
    "sizeof(CrashFrame) == 64",
    "Stage::kCredentialAccepted",
    "program_counter_offset",
    "link_register_offset",
    "address_flags",
):
    if required not in protocol and required not in client and required not in helper:
        raise SystemExit(f"V5.0 protocol contract missing: {required}")
if "oem_load_base" in protocol:
    raise SystemExit("V5.0 protocol still exposes a raw OEM ASLR base")
for required in (
    "bool authorization_failed = false;",
    "if (!hwRet.isOk() || authorization_failed)",
    "if (!binder_result.isOk())",
):
    if required not in decrypt:
        raise SystemExit(f"V5.0 TeamWin authorization guard missing: {required}")
for required in (
    "GetKeyUpgradeLock()",
    "GetKeyDirsToCommit()",
):
    if required not in key_storage:
        raise SystemExit(f"V5.0 inherited KeyStorage hardening missing: {required}")
if "malformed pKMblob prefix" not in keymaster:
    raise SystemExit("V5.0 inherited malformed pKMblob-origin rejection missing")
for forbidden in (
    "static std::mutex key_upgrade_lock;",
    "static std::vector<std::string> key_dirs_to_commit;",
):
    if forbidden in key_storage:
        raise SystemExit(f"V5.0 namespace global survived: {forbidden}")
for marker in ("[H40 FSCRYPTMODE]", "[H40 FSCRYPTLAZY]"):
    if marker not in fscrypt:
        raise SystemExit(f"V5.0 lost inherited FsCrypt marker: {marker}")
if "LOCAL_SHARED_LIBRARIES := libc++ libdl liblog libkeyutils libcrypto" not in android_mk:
    raise SystemExit("V5.0 helper build contract missing libcrypto")
if "# H.40 V5.0 exact credential gate." not in android_mk:
    raise SystemExit("V5.0 helper version marker missing")

print("Applied H.40 V5.0 DE-path compatibility stack")
print("  inherited: V4.9 DE/user-map/KeyStorage hardening and UI resources")
print("  credential: exact-H.40 isolated gate; no OEM CE-key mutation")
print("  decryption: bounded TeamWin synthetic-password and KeyStorage worker")
print("  proof: CE policy key must be present before adapter unlock completes")
