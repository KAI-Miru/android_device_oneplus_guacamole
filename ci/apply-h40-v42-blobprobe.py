#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v42-blobprobe.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
base_transform = repo_root / "ci" / "apply-h40-v44-upgradeparams-base.py"
if not base_transform.is_file():
    raise SystemExit(f"V4.5 base transform missing: {base_transform}")

# Apply the exact V4.4 transform first.  V4.5 is deliberately a recovery-runtime
# delta only: it changes the build identity visible to QTI Keymaster before the
# H.40 Keymaster service starts, while retaining all V4.1-V4.4 blob/parameter
# compatibility and leaving the persistent metadata key files untouched.
subprocess.run(
    [sys.executable, str(base_transform), sys.argv[1], sys.argv[2]],
    check=True,
)

recovery_cpp_path = Path(sys.argv[1]) / "oplus_h40_decrypt.cpp"
recovery_cpp = recovery_cpp_path.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# V4.4 physical result:
#   raw QTI blob is recognized and begin/getKeyCharacteristics return
#   KEY_REQUIRES_UPGRADE (-62); upgradeKey receives the purpose-filtered
#   Keystore2-compatible parameter set, but returns INVALID_ARGUMENT (-38).
#
# HIDL Keymaster 4.0 requires INVALID_ARGUMENT when a key is bound to a newer
# OS version / OS patch level than the current Keymaster environment.  H.40's
# libqtikeymaster4 reads ro.build.version.release,
# ro.build.version.security_patch and ro.vendor.build.security_patch when its
# service starts.  The stock recovery ramdisk advertises the old H.40 Android
# identity, while the metadata key belongs to the current Android 14 system.
#
# Hand QTI Keymaster the current system-side identity before it starts.  Keep
# the H.40 vendor patch level untouched, because the device still uses the H.40
# vendor.  The override is recovery-session-only and no key/blob file is
# modified by this transform.

recovery_cpp = replace_once(
    recovery_cpp,
    '#include <sys/stat.h>\n#include <unistd.h>\n',
    '#include <sys/stat.h>\n#include <sys/wait.h>\n#include <unistd.h>\n',
    "V4.5 resetprop wait include",
)

setprop_anchor = '''bool SetProperty(const char* name, const char* value) {
    if (property_set(name, value) == 0) return true;
    LOGERR("Oplus H.40 decrypt: failed to set %s=%s\\n", name, value);
    return false;
}

'''
identity_helpers = r'''bool SetProperty(const char* name, const char* value) {
    if (property_set(name, value) == 0) return true;
    LOGERR("Oplus H.40 decrypt: failed to set %s=%s\n", name, value);
    return false;
}

bool RunResetprop(const char* name, const char* value) {
    const pid_t pid = fork();
    if (pid < 0) {
        LOGERR("[H40 PORTIDENTITY] fork failed for %s: %s\n", name, strerror(errno));
        return false;
    }
    if (pid == 0) {
        execl("/system/bin/resetprop", "resetprop", name, value,
              static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        LOGERR("[H40 PORTIDENTITY] waitpid failed for %s: %s\n", name, strerror(errno));
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGERR("[H40 PORTIDENTITY] resetprop failed for %s, status=%d\n", name, status);
        return false;
    }

    const std::string actual = ReadProperty(name);
    if (actual != value) {
        LOGERR("[H40 PORTIDENTITY] resetprop verification failed for %s: got=%s expected=%s\n",
               name, actual.c_str(), value);
        return false;
    }
    return true;
}

bool PrepareKeymasterBuildIdentity() {
    constexpr char kSystemRelease[] = "14";
    constexpr char kSystemSecurityPatch[] = "2025-03-01";

    const std::string keymaster_state = ReadProperty("init.svc.keymaster-4-0");
    if (keymaster_state == "running" || keymaster_state == "restarting") {
        LOGERR("[H40 PORTIDENTITY] refusing late identity change: keymaster-4-0=%s\n",
               keymaster_state.c_str());
        return false;
    }

    const std::string before_release = ReadProperty("ro.build.version.release");
    const std::string before_os_patch = ReadProperty("ro.build.version.security_patch");
    const std::string vendor_patch = ReadProperty("ro.vendor.build.security_patch");
    LOGINFO("[H40 PORTIDENTITY] before: release=%s osPatch=%s vendorPatch=%s keymasterState=%s\n",
            before_release.c_str(), before_os_patch.c_str(), vendor_patch.c_str(),
            keymaster_state.c_str());

    if (!RunResetprop("ro.build.version.release", kSystemRelease)) return false;
    if (!RunResetprop("ro.build.version.security_patch", kSystemSecurityPatch)) return false;

    const std::string after_release = ReadProperty("ro.build.version.release");
    const std::string after_os_patch = ReadProperty("ro.build.version.security_patch");
    const std::string after_vendor_patch = ReadProperty("ro.vendor.build.security_patch");
    if (after_vendor_patch != vendor_patch) {
        LOGERR("[H40 PORTIDENTITY] vendor patch changed unexpectedly: before=%s after=%s\n",
               vendor_patch.c_str(), after_vendor_patch.c_str());
        return false;
    }
    if (after_release != kSystemRelease || after_os_patch != kSystemSecurityPatch) {
        LOGERR("[H40 PORTIDENTITY] final identity verification failed\n");
        return false;
    }

    LOGINFO("[H40 PORTIDENTITY] after: release=%s osPatch=%s vendorPatch=%s\n",
            after_release.c_str(), after_os_patch.c_str(), after_vendor_patch.c_str());
    return true;
}

'''
recovery_cpp = replace_once(
    recovery_cpp,
    setprop_anchor,
    identity_helpers,
    "V4.5 Keymaster build-identity helpers",
)

services_old = '''    // This is H.40 stock recovery's own trigger. It starts the exact qseecomd,
    // keymaster-4-0, and hwservicemanager definitions from stock init.rc.
    if (!SetProperty("enable.qseecomd.service", "1")) return false;
'''
services_new = '''    // QTI Keymaster snapshots the Android OS/security-patch identity while the
    // service is constructed.  Set the current system-side identity before the
    // H.40 stock recovery trigger starts Keymaster; keep vendor patch untouched.
    if (!PrepareKeymasterBuildIdentity()) return false;

    // This is H.40 stock recovery's own trigger. It starts the exact qseecomd,
    // keymaster-4-0, and hwservicemanager definitions from stock init.rc.
    if (!SetProperty("enable.qseecomd.service", "1")) return false;
'''
recovery_cpp = replace_once(
    recovery_cpp,
    services_old,
    services_new,
    "V4.5 pre-Keymaster identity handoff",
)

recovery_cpp_path.write_text(recovery_cpp)

final_recovery = recovery_cpp_path.read_text()
final_vold = (Path(sys.argv[2]) / "Keymaster.cpp").read_text()

for needle in (
    '[H40 BLOBPREFIX] begin:',
    '[H40 BLOBPROBE] characteristics:',
    '[H40 UPGRADEPARAMS] begin:',
    '[H40 UPGRADEPARAMS] upgrade:',
):
    if needle not in final_vold:
        raise SystemExit(f"V4.5 lost V4.4 Keymaster contract: {needle}")

for needle in (
    '#include <sys/wait.h>',
    'bool PrepareKeymasterBuildIdentity()',
    '[H40 PORTIDENTITY] before:',
    '[H40 PORTIDENTITY] after:',
    'RunResetprop("ro.build.version.release", kSystemRelease)',
    'RunResetprop("ro.build.version.security_patch", kSystemSecurityPatch)',
    'constexpr char kSystemRelease[] = "14";',
    'constexpr char kSystemSecurityPatch[] = "2025-03-01";',
):
    if needle not in final_recovery:
        raise SystemExit(f"V4.5 port-identity contract missing: {needle}")

if final_recovery.count('RunResetprop("') != 2:
    raise SystemExit("V4.5 must override exactly two read-only build properties")
if 'RunResetprop("ro.vendor.build.security_patch"' in final_recovery:
    raise SystemExit("V4.5 must not override H.40 vendor patch level")
if '/metadata/' in identity_helpers or 'keymaster_key_blob' in identity_helpers:
    raise SystemExit("V4.5 identity helper must not touch persistent metadata/key blobs")

identity_call = final_recovery.find('if (!PrepareKeymasterBuildIdentity()) return false;')
qsee_trigger = final_recovery.find('if (!SetProperty("enable.qseecomd.service", "1")) return false;')
if identity_call < 0 or qsee_trigger < 0 or identity_call >= qsee_trigger:
    raise SystemExit("V4.5 identity handoff must run before the QSEE/Keymaster trigger")

print("Applied H.40 V4.5 pre-Keymaster port identity")
print("  V4.4 pKMblob/upgrade-parameter compatibility: retained")
print("  QTI Keymaster OS release: 14")
print("  QTI Keymaster OS security patch: 2025-03-01")
print("  H.40 vendor security patch: preserved")
print("  persistent metadata/key blobs changed: no")
