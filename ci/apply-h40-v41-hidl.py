#!/usr/bin/env python3
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys

if len(sys.argv) != 4:
    raise SystemExit(
        "usage: apply-h40-v41-hidl.py RECOVERY_ROOT VOLD_ROOT HIDL_REFERENCE_ROOT"
    )

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
reference_root = Path(sys.argv[3])
this_dir = Path(__file__).resolve().parent


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    h = hashlib.sha1()
    h.update(f"blob {len(data)}\0".encode())
    h.update(data)
    return h.hexdigest()


def require_blob(path: Path, expected: str, label: str) -> None:
    actual = git_blob_sha1(path)
    if actual != expected:
        raise SystemExit(f"{label}: blob mismatch: expected {expected}, got {actual}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# First build the already-reviewed V4 structure: TeamWin owns metadata mapping,
# while the Oplus H.40 ABI owns the later DE/password/CE handoff.
subprocess.run(
    [sys.executable, str(this_dir / "apply-h40-v4-hybrid.py"), str(recovery_root)],
    check=True,
)

# V4.0 proved that the Android-12 Keystore2 AIDL client crashes on this H.40
# environment at Keymaster construction, even after keystore2 is registered.
# V4.1 therefore keeps the same four-file TeamWin KeyStorage reader but talks
# directly to H.40's already-working Keymaster 4.0 HIDL service.
cpp_path = recovery_root / "oplus_h40_decrypt.cpp"
cpp = cpp_path.read_text()
old_runtime = '''    // TeamWin android_system_vold 12.1 retrieves the four-file metadata key
    // through keystore2. The H.40 ramdisk does not ship that service, so the
    // hybrid image supplies the matching TWRP keystore2 runtime under /system/tw.
    if (!SetProperty("ctl.start", "keystore2-v4") ||
        !WaitForPropertyValue("init.svc.keystore2-v4", "running",
                              "TWRP keystore2 runtime")) {
        return FailActive("TWRP keystore2 runtime unavailable");
    }
'''
new_runtime = '''    // V4.1: TeamWin KeyStorage is compiled against a direct HIDL Keymaster 4.0
    // backend. PrepareMetadataServices() above has already brought up the H.40
    // qsee/keymaster/hwservicemanager stack, so no Keystore2 Binder daemon is
    // needed for metadata-key retrieval.
    LOGINFO("Oplus H.40 v4.1 metadata backend: direct HIDL Keymaster 4.0\\n");
'''
cpp = replace_once(cpp, old_runtime, new_runtime, "remove Keystore2 runtime gate")
cpp_path.write_text(cpp)

# Pin the exact reviewed direct-HIDL implementation.  We transplant only the
# Keymaster wrapper, not the fork's Vivo-specific Decrypt/FsCrypt changes.
teamwin_expected = {
    "Keymaster.cpp": "4781d9114792e98d566a153bd279ea52501b9c1d",
    "Keymaster.h": "47bf4a26c6b45a8f65d7b2eaed41de3ce6a9f6d2",
    "Android.bp": "376157b4880cf35bb715433a1c88507a91d23f6a",
}
reference_expected = {
    "Keymaster.cpp": "c3c230c793501db721854c11082a361980e05955",
    "Keymaster.h": "0e4d01a00081b31e2fb469cf203933cb70764b0a",
}

for name, expected in teamwin_expected.items():
    require_blob(vold_root / name, expected, f"TeamWin base {name}")
for name, expected in reference_expected.items():
    require_blob(reference_root / name, expected, f"HIDL reference {name}")

for name in ("Keymaster.cpp", "Keymaster.h"):
    shutil.copyfile(reference_root / name, vold_root / name)
    require_blob(vold_root / name, reference_expected[name], f"installed HIDL {name}")

# Add only the two libraries newly required by the HIDL Keymaster wrapper to
# libvold.  Leave the rest of TeamWin's vold tree and dependencies untouched.
bp_path = vold_root / "Android.bp"
bp = bp_path.read_text()
start_marker = 'cc_library_static {\n    name: "libvold",'
end_marker = '\ncc_binary {\n    name: "vold",'
start = bp.find(start_marker)
end = bp.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("unable to isolate libvold Android.bp block")
block = bp[start:end]
block = replace_once(
    block,
    '        "android.hardware.keymaster@4.1",\n',
    '        "android.hardware.keymaster@4.0",\n        "android.hardware.keymaster@4.1",\n',
    "libvold Keymaster 4.0 dependency",
)
block = replace_once(
    block,
    '        "libkeymaster4_1support",\n',
    '        "libkeymaster4support",\n        "libkeymaster4_1support",\n',
    "libvold Keymaster 4.0 support dependency",
)
bp = bp[:start] + block + bp[end:]
bp_path.write_text(bp)

# Contract checks: the metadata path must use raw HIDL, not the crashing AIDL
# Keymaster wrapper.  Generic TWRP code elsewhere may still link binder/keystore
# interfaces, so we assert against the wrapper implementation itself.
km_cpp = (vold_root / "Keymaster.cpp").read_text()
km_h = (vold_root / "Keymaster.h").read_text()
if "IKeymasterDevice40::getService(\"default\")" not in km_cpp:
    raise SystemExit("direct HIDL default Keymaster lookup missing")
if "AServiceManager_waitForService" in km_cpp or "IKeystoreService" in km_h:
    raise SystemExit("Keystore2 AIDL Keymaster wrapper survived V4.1 transplant")
if "Oplus H.40 v4.1 metadata backend: direct HIDL Keymaster 4.0" not in cpp:
    raise SystemExit("V4.1 runtime marker missing")
if "keystore2-v4" in cpp or "TWRP keystore2 runtime unavailable" in cpp:
    raise SystemExit("V4.0 Keystore2 runtime dependency survived V4.1")

print("Applied H.40 V4.1 direct-HIDL metadata backend")
print("  metadata format: TeamWin four-file KeyStorage")
print("  metadata keymaster: android.hardware.keymaster@4.0::IKeymasterDevice/default")
print("  DE/password/CE: Oplus H.40 libdecrypt_recovery")
print("  Keystore2 runtime: not required")
