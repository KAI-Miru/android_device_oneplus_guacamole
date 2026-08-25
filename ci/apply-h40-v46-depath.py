#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v46-depath.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
steps = [
    ("V4.5 validated base", repo_root / "ci" / "apply-h40-v42-blobprobe.py"),
    ("V4.6 dynamic installed-system identity", repo_root / "ci" / "apply-h40-v46-portidentity.py"),
    ("V4.6 lazy FsCrypt/key globals", repo_root / "ci" / "apply-h40-v46-fscrypt-lazy.py"),
    ("V4.6 pKMblob wrapped-key export", repo_root / "ci" / "apply-h40-v46-export-prefix.py"),
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
        raise SystemExit(f"V4.6 lost Keymaster compatibility marker: {marker}")

for marker in (
    "[H40 PORTIDENTITY] source:",
    "[H40 PORTIDENTITY] applied:",
):
    if marker not in recovery:
        raise SystemExit(f"V4.6 dynamic port-identity marker missing: {marker}")

for marker in (
    "[H40 FSCRYPTLAZY] DE policies ready:",
    "[H40 FSCRYPTLAZY] DE policy insertion complete:",
):
    if marker not in fscrypt:
        raise SystemExit(f"V4.6 lazy FsCrypt marker missing: {marker}")

for forbidden in (
    'constexpr char kSystemRelease[] = "14";',
    'constexpr char kSystemSecurityPatch[] = "2025-03-01";',
):
    if forbidden in recovery:
        raise SystemExit(f"V4.6 hardcoded port identity survived: {forbidden}")

if "Using key directly" in keymaster:
    raise SystemExit("V4.6 unsafe wrapped-key export fallback survived")
if keymaster.count("IsUsableHidlKeyBlob(") != 9:
    raise SystemExit("V4.6 expected helper plus eight fail-closed HIDL consumers")
for forbidden_guard in (
    "if (oldBlobView.softKeyMint)",
    "if (blobView.softKeyMint)",
    "if (upgradedBlobView.softKeyMint)",
):
    if forbidden_guard in keymaster:
        raise SystemExit(f"V4.6 softKeyMint-only guard survived: {forbidden_guard}")
for forbidden in (
    "static std::mutex key_upgrade_lock;",
    "static std::vector<std::string> key_dirs_to_commit;",
):
    if forbidden in key_storage:
        raise SystemExit(f"V4.6 unsafe KeyStorage namespace object survived: {forbidden}")
for required in (
    "GetKeyUpgradeLock()",
    "GetKeyDirsToCommit()",
):
    if required not in key_storage:
        raise SystemExit(f"V4.6 lazy KeyStorage accessor missing: {required}")
if "std::map<userid_t, EncryptionPolicy> s_de_policies;" in fscrypt:
    raise SystemExit("V4.6 unsafe namespace-scope DE map survived")
if "std::map<userid_t, EncryptionPolicy> s_ce_policies;" in fscrypt:
    raise SystemExit("V4.6 unsafe namespace-scope CE map survived")

print("Applied H.40 V4.6 DE-path compatibility stack")
print("  base: physically validated V4.5 / V4.1-V4.4 retained")
print("  fix 1: dynamic installed-system Keymaster identity")
print("  fix 2: recovery-safe lazy FsCrypt/KeyStorage globals")
print("  fix 3: malformed-aware pKMblob wrapped storage-key export")
