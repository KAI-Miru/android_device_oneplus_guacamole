#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v47-depath.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
steps = [
    ("V4.6 validated DE-path base", repo_root / "ci" / "apply-h40-v46-depath.py"),
    ("V4.7 fscrypt keyring and key-mode fix",
     repo_root / "ci" / "apply-h40-v47-fscrypt-keyring.py"),
]
for label, script in steps:
    if not script.is_file():
        raise SystemExit(f"{label} transform missing: {script}")
    subprocess.run([sys.executable, str(script), sys.argv[1], sys.argv[2]], check=True)

recovery = (Path(sys.argv[1]) / "oplus_h40_decrypt.cpp").read_text()
vold_root = Path(sys.argv[2])
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
        raise SystemExit(f"V4.7 lost Keymaster compatibility marker: {marker}")

for marker in (
    "[H40 PORTIDENTITY] source:",
    "[H40 PORTIDENTITY] applied:",
):
    if marker not in recovery:
        raise SystemExit(f"V4.7 dynamic port-identity marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTLAZY] DE policies ready:",
    "[H40 FSCRYPTLAZY] DE policy insertion complete:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.7 lazy FsCrypt marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTKEYRING] existing:",
    "[H40 FSCRYPTKEYRING] created:",
    "[H40 FSCRYPTKEYRING] ready before TWRP metadata decrypt",
    "[H40 FSCRYPTKEYRING] ready before setup_de_ce(0)",
):
    if marker not in recovery:
        raise SystemExit(f"V4.7 fscrypt keyring marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTMODE] data options:",
    "[H40 FSCRYPTMODE] system key install failed without mode fallback:",
    "[H40 FSCRYPTMODE] system key installed without mode fallback:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.7 deterministic key-mode marker missing: {marker}")

for forbidden in (
    'constexpr char kSystemRelease[] = "14";',
    'constexpr char kSystemSecurityPatch[] = "2025-03-01";',
):
    if forbidden in recovery:
        raise SystemExit(f"V4.7 hardcoded port identity survived: {forbidden}")

if "Using key directly" in keymaster:
    raise SystemExit("V4.7 unsafe wrapped-key export fallback survived")
if keymaster.count("IsUsableHidlKeyBlob(") != 9:
    raise SystemExit("V4.7 expected helper plus eight fail-closed HIDL consumers")
for forbidden_guard in (
    "if (oldBlobView.softKeyMint)",
    "if (blobView.softKeyMint)",
    "if (upgradedBlobView.softKeyMint)",
):
    if forbidden_guard in keymaster:
        raise SystemExit(f"V4.7 softKeyMint-only guard survived: {forbidden_guard}")
for forbidden in (
    "static std::mutex key_upgrade_lock;",
    "static std::vector<std::string> key_dirs_to_commit;",
):
    if forbidden in key_storage:
        raise SystemExit(f"V4.7 unsafe KeyStorage namespace object survived: {forbidden}")
for required in (
    "GetKeyUpgradeLock()",
    "GetKeyDirsToCommit()",
):
    if required not in key_storage:
        raise SystemExit(f"V4.7 lazy KeyStorage accessor missing: {required}")
if "std::map<userid_t, EncryptionPolicy> s_de_policies;" in fscrypt:
    raise SystemExit("V4.7 unsafe namespace-scope DE map survived")
if "std::map<userid_t, EncryptionPolicy> s_ce_policies;" in fscrypt:
    raise SystemExit("V4.7 unsafe namespace-scope CE map survived")

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
        raise SystemExit(f"V4.7 unsafe raw/wrapped retry survived: {forbidden}")

print("Applied H.40 V4.7 DE-path compatibility stack")
print("  base: physically validated V4.5 / V4.1-V4.4 retained")
print("  V4.6: identity, lazy globals and pKMblob export retained")
print("  V4.7 fix 1: recovery session fscrypt keyring before metadata/DE setup")
print("  V4.7 fix 2: explicit raw/wrapped mode with no global fallback")
