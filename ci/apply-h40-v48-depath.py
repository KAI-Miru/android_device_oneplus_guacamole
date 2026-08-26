#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v48-depath.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
steps = [
    ("V4.7 validated DE-path base", repo_root / "ci" / "apply-h40-v47-depath.py"),
    (
        "V4.8 canonical secondary-user coexistence",
        repo_root / "ci" / "apply-h40-v48-secondary-user.py",
    ),
]
for label, script in steps:
    if not script.is_file():
        raise SystemExit(f"{label} transform missing: {script}")
    subprocess.run([sys.executable, str(script), sys.argv[1], sys.argv[2]], check=True)

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter = (recovery_root / "oplus_h40_decrypt.cpp").read_text()
manager = (recovery_root / "partitionmanager.cpp").read_text()
keymaster = (vold_root / "Keymaster.cpp").read_text()
fscrypt = (vold_root / "FsCrypt.cpp").read_text()
key_storage = (vold_root / "KeyStorage.cpp").read_text()

for marker in (
    "[H40 KMCOMPAT] constructor: enumerating Keymaster 4.x devices",
    "[H40 BLOBPREFIX] begin:",
    "[H40 BLOBPROBE] characteristics:",
    "[H40 UPGRADEPARAMS] begin:",
    "[H40 UPGRADEPARAMS] upgrade:",
    "[H40 BLOBPREFIX] export:",
    "[H40 BLOBPREFIX] export result:",
    "malformed pKMblob prefix",
):
    if marker not in keymaster:
        raise SystemExit(f"V4.8 lost Keymaster compatibility marker: {marker}")

for marker in (
    "[H40 PORTIDENTITY] source:",
    "[H40 PORTIDENTITY] applied:",
):
    if marker not in adapter:
        raise SystemExit(f"V4.8 dynamic port-identity marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTLAZY] DE policies ready:",
    "[H40 FSCRYPTLAZY] DE policy insertion complete:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.8 lazy FsCrypt marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTKEYRING] existing:",
    "[H40 FSCRYPTKEYRING] created:",
    "[H40 FSCRYPTKEYRING] ready before TWRP metadata decrypt",
    "[H40 FSCRYPTKEYRING] ready before setup_de_ce(0)",
):
    if marker not in adapter:
        raise SystemExit(f"V4.8 fscrypt keyring marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTMODE] data options:",
    "[H40 FSCRYPTMODE] system key install failed without mode fallback:",
    "[H40 FSCRYPTMODE] system key installed without mode fallback:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.8 deterministic key-mode marker missing: {marker}")

for forbidden in (
    'constexpr char kSystemRelease[] = "14";',
    'constexpr char kSystemSecurityPatch[] = "2025-03-01";',
):
    if forbidden in adapter:
        raise SystemExit(f"V4.8 hardcoded port identity survived: {forbidden}")

if "Using key directly" in keymaster:
    raise SystemExit("V4.8 unsafe wrapped-key export fallback survived")
if keymaster.count("IsUsableHidlKeyBlob(") != 9:
    raise SystemExit("V4.8 expected helper plus eight fail-closed HIDL consumers")
for forbidden_guard in (
    "if (oldBlobView.softKeyMint)",
    "if (blobView.softKeyMint)",
    "if (upgradedBlobView.softKeyMint)",
):
    if forbidden_guard in keymaster:
        raise SystemExit(f"V4.8 softKeyMint-only guard survived: {forbidden_guard}")
for forbidden in (
    "static std::mutex key_upgrade_lock;",
    "static std::vector<std::string> key_dirs_to_commit;",
):
    if forbidden in key_storage:
        raise SystemExit(f"V4.8 unsafe KeyStorage namespace object survived: {forbidden}")
for required in (
    "GetKeyUpgradeLock()",
    "GetKeyDirsToCommit()",
):
    if required not in key_storage:
        raise SystemExit(f"V4.8 lazy KeyStorage accessor missing: {required}")
if "std::map<userid_t, EncryptionPolicy> s_de_policies;" in fscrypt:
    raise SystemExit("V4.8 unsafe namespace-scope DE map survived")
if "std::map<userid_t, EncryptionPolicy> s_ce_policies;" in fscrypt:
    raise SystemExit("V4.8 unsafe namespace-scope CE map survived")

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
        raise SystemExit(f"V4.8 unsafe raw/wrapped retry survived: {forbidden}")

scan_start = adapter.index("bool ScanSingleUserDirectory(")
scan_end = adapter.index("\nbool ValidateSingleUser0DeLayout()", scan_start)
scan_body = adapter[scan_start:scan_end]
for required in (
    "if (user_id == INT_MAX)",
    "Oplus H.40 user0-only mode refusing malformed user entry %s/%s",
    "if (user_id != 0)",
    "[H40 USERMAP] ignoring secondary user id %d from %s/%s; ",
    "user0-only decrypt remains enforced",
    "continue;",
):
    if required not in scan_body:
        raise SystemExit(f"V4.8 secondary-user scan contract missing: {required}")
secondary_start = scan_body.index("if (user_id != 0)")
secondary_end = scan_body.index("\n        }", secondary_start)
secondary_body = scan_body[secondary_start:secondary_end]
if "errno = 0;" not in secondary_body or \
        secondary_body.index("errno = 0;") > secondary_body.index("continue;"):
    raise SystemExit("V4.8 secondary-user branch does not clear errno before continue")
if "refusing secondary/unsupported user id" in adapter:
    raise SystemExit("V4.8 obsolete all-secondary fatal guard survived")
if adapter.count("*user_id = INT_MAX;") != 2:
    raise SystemExit("V4.8 malformed canonical-ID rejection was weakened")

layout_start = adapter.index("bool ValidateSingleUser0DeLayout()")
layout_end = adapter.index("\nbool CheckFscryptKeyPresent(", layout_start)
layout_body = adapter[layout_start:layout_end]
for required in (
    'CheckReadableFile("/data/unencrypted/key/version")',
    'CheckReadableDirectory("/data/system_de/0")',
    'CheckReadableFile("/data/system/users/0.xml")',
    'ScanSingleUserDirectory("/data/system_de", "", true)',
    'ScanSingleUserDirectory("/data/system/users", "", false)',
    'ScanSingleUserDirectory("/data/system/users", ".xml", true)',
):
    if required not in layout_body:
        raise SystemExit(f"V4.8 user0 layout contract missing: {required}")

credential_start = adapter.index("Result DecryptUser(")
credential_body = adapter[credential_start:]
if "if (user_id != 0)" not in credential_body or \
        "refusing credential for user %d" not in credential_body:
    raise SystemExit("V4.8 adapter nonzero-user credential refusal was weakened")
for required in (
    "if (oplus_active && user_id != 0)",
    'user0.userId = "0";',
    "user_list->clear();",
    "user_list->push_back(user0);",
    "Oplus H.40 user 0 decrypted; secondary-user sweep disabled",
):
    if required not in manager:
        raise SystemExit(f"V4.8 partition-manager user0-only contract missing: {required}")
synth_start = manager.index("std::vector<users_struct>* user_list = Get_Users_List()")
synth_end = manager.index("Check_Users_Decryption_Status();", synth_start)
synth_body = manager[synth_start:synth_end]
if synth_body.count("user_list->push_back(") != 1:
    raise SystemExit("V4.8 synthesized TWRP user map is no longer exactly user0-only")

print("Applied H.40 V4.8 DE-path compatibility stack")
print("  base: V4.7 keyring and deterministic key mode retained")
print("  V4.8: canonical secondary profiles coexist with user0-only discovery")
print("  boundary: malformed IDs fail closed; nonzero credentials remain refused")
